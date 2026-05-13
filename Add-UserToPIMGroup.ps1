#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Onboards a user to a PIM-eligible security group and removes their direct Entra directory role assignments.

.DESCRIPTION
    1. Adds the user as a PIM-eligible member of the specified security group (1-year eligibility).
    2. Removes all direct/active Entra directory role assignments from the user.

    After running this script the user will need to activate their group membership
    via PIM (My Roles > Groups) to regain directory roles through the group.

.PARAMETER UserPrincipalName
    The UPN of the user to onboard (e.g. user@contoso.com).

.PARAMETER GroupName
    The display name of the PIM-enabled security group (e.g. PIM_Security_Team).

.EXAMPLE
    .\Add-UserToPIMGroup.ps1 -UserPrincipalName "john@contoso.com" -GroupName "PIM_Security_Team"

.NOTES
    Requires Microsoft Graph PowerShell SDK.
    You must be a Privileged Role Administrator or Global Administrator.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [string]$GroupName
)

$ErrorActionPreference = "Stop"

# ── 1. Connect to Microsoft Graph ────────────────────────────────────────────
$requiredScopes = @(
    "User.Read.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup"
)

Write-Host "`n[1/5] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
Write-Host "  Connected.`n" -ForegroundColor Green

# ── 2. Resolve user and group ────────────────────────────────────────────────
Write-Host "[2/5] Resolving user and group..." -ForegroundColor Cyan

$user = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
Write-Host "  User  : $($user.DisplayName) ($($user.UserPrincipalName)) [Id: $($user.Id)]" -ForegroundColor Green

$escapedGroupName = $GroupName.Replace("'", "''")
$groups = Get-MgGroup -Filter "displayName eq '$escapedGroupName'" -All -ErrorAction Stop

if (-not $groups -or $groups.Count -eq 0) {
    throw "No group found with display name '$GroupName'."
}
if ($groups.Count -gt 1) {
    throw "Multiple groups found with display name '$GroupName'. Use a unique name."
}

$group = $groups[0]

if (-not $group.SecurityEnabled) {
    throw "Group '$GroupName' is not a security group."
}
if (-not $group.IsAssignableToRole) {
    throw "Group '$GroupName' is not role-assignable. It must be created with IsAssignableToRole = true."
}

Write-Host "  Group : $($group.DisplayName) [Id: $($group.Id)]`n" -ForegroundColor Green

# ── 3. Add user as PIM-eligible member of the group ──────────────────────────
Write-Host "[3/5] Adding PIM-eligible membership..." -ForegroundColor Cyan

# Check for existing eligibility
$existingEligibility = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance `
    -Filter "groupId eq '$($group.Id)' and principalId eq '$($user.Id)'" `
    -ErrorAction SilentlyContinue

if ($existingEligibility) {
    Write-Host "  User already has eligible membership on '$GroupName'. Skipping.`n" -ForegroundColor DarkYellow
}
else {
    $startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endTime   = (Get-Date).ToUniversalTime().AddYears(1).ToString("yyyy-MM-ddTHH:mm:ssZ")

    $eligibilityParams = @{
        AccessId      = "member"
        PrincipalId   = $user.Id
        GroupId       = $group.Id
        Action        = "adminAssign"
        Justification = "PIM onboarding - eligible membership via Add-UserToPIMGroup script"
        ScheduleInfo  = @{
            StartDateTime = $startTime
            Expiration    = @{
                Type        = "afterDateTime"
                EndDateTime = $endTime
            }
        }
    }

    if ($PSCmdlet.ShouldProcess("$($user.DisplayName) -> $GroupName", "Create PIM eligible membership")) {
        New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest `
            -BodyParameter $eligibilityParams -ErrorAction Stop | Out-Null
        Write-Host "  [OK] Eligible membership created (expires $endTime).`n" -ForegroundColor Green
    }
}

# ── 4. Get direct/active directory role assignments ──────────────────────────
Write-Host "[4/5] Retrieving direct active directory role assignments..." -ForegroundColor Cyan

$directAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance `
    -Filter "principalId eq '$($user.Id)'" -All -ErrorAction Stop |
    Where-Object { $_.MemberType -eq "Direct" }

if (-not $directAssignments -or $directAssignments.Count -eq 0) {
    Write-Host "  No direct active role assignments found. Nothing to remove.`n" -ForegroundColor DarkYellow
}
else {
    # Fetch role definitions for display
    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
    $roleLookup = @{}
    foreach ($rd in $roleDefinitions) { $roleLookup[$rd.Id] = $rd.DisplayName }

    Write-Host "  Found $($directAssignments.Count) direct active assignment(s):" -ForegroundColor Yellow
    foreach ($a in $directAssignments) {
        $roleName = $roleLookup[$a.RoleDefinitionId]
        if (-not $roleName) { $roleName = $a.RoleDefinitionId }
        Write-Host "    - $roleName (scope: $($a.DirectoryScopeId))" -ForegroundColor Yellow
    }
    Write-Host ""

    # ── 5. Remove each direct assignment (save rollback file first) ─────────
    Write-Host "[5/5] Removing direct active role assignments..." -ForegroundColor Cyan

    # Save rollback data before removing anything
    $rollbackDir = Join-Path $PSScriptRoot "Rollback"
    if (-not (Test-Path $rollbackDir)) { New-Item -Path $rollbackDir -ItemType Directory -Force | Out-Null }

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $safeUpn   = $UserPrincipalName -replace '[^\w@.]', '_'
    $rollbackFile = Join-Path $rollbackDir "${safeUpn}_${timestamp}.json"

    $rollbackData = @{
        UserPrincipalName = $UserPrincipalName
        UserId            = $user.Id
        DisplayName       = $user.DisplayName
        GroupName         = $GroupName
        GroupId           = $group.Id
        Timestamp         = (Get-Date).ToUniversalTime().ToString("o")
        RemovedAssignments = @(
            foreach ($a in $directAssignments) {
                @{
                    RoleDefinitionId         = $a.RoleDefinitionId
                    RoleName                 = $roleLookup[$a.RoleDefinitionId]
                    DirectoryScopeId         = $a.DirectoryScopeId
                    RoleAssignmentScheduleId = $a.RoleAssignmentScheduleId
                }
            }
        )
    }

    $rollbackData | ConvertTo-Json -Depth 5 | Set-Content -Path $rollbackFile -Encoding UTF8
    Write-Host "  Rollback file saved: $rollbackFile" -ForegroundColor Magenta

    foreach ($assignment in $directAssignments) {
        $roleName = $roleLookup[$assignment.RoleDefinitionId]
        if (-not $roleName) { $roleName = $assignment.RoleDefinitionId }

        if ($PSCmdlet.ShouldProcess($user.DisplayName, "Remove direct role '$roleName'")) {
            try {
                $removeParams = @{
                    Action           = "adminRemove"
                    PrincipalId      = $user.Id
                    RoleDefinitionId = $assignment.RoleDefinitionId
                    DirectoryScopeId = $assignment.DirectoryScopeId
                    Justification    = "Migrated to PIM group '$GroupName' - removing direct assignment"
                }

                # Use the schedule ID if available for precise targeting
                if ($assignment.RoleAssignmentScheduleId) {
                    $removeParams["TargetScheduleId"] = $assignment.RoleAssignmentScheduleId
                }

                New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest `
                    -BodyParameter $removeParams -ErrorAction Stop | Out-Null
                Write-Host "  [OK] Removed: $roleName" -ForegroundColor Green
            }
            catch {
                Write-Host "  [ERROR] Failed to remove '$roleName': $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host @"

Summary for $($user.DisplayName):
  - PIM-eligible membership: $GroupName (1-year eligibility)
  - Direct role assignments removed: $($directAssignments.Count)

IMPORTANT: The user must activate group membership via PIM to regain roles:
  My Roles > Groups > Activate '$GroupName'
"@
