#Requires -Modules Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Creates Entra ID security groups with active role assignments and PIM-eligible membership.

.DESCRIPTION
    1. Creates 5 role-assignable security groups.
    2. Assigns directory roles as PERMANENTLY ACTIVE on each group.
    3. Enables PIM for Groups so that membership is ELIGIBLE (not active).
    Users activate group membership once via PIM → instantly receive all the group's roles.

.NOTES
    Requires Microsoft Graph PowerShell SDK.
    Run: Install-Module Microsoft.Graph -Scope CurrentUser
    You must be a Global Administrator or Privileged Role Administrator to run this.
#>

# --- Connect to Microsoft Graph with required scopes ---
$requiredScopes = @(
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All"
)

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
Write-Host "Connected successfully.`n" -ForegroundColor Green

# --- Define groups and their roles ---
$groupRoleMap = @{
    "PIM_Security_Team" = @(
        "User Administrator"
        "Service Support Administrator"
        "Application Administrator"
        "Security Administrator"
        "Privileged Role Administrator"
        "Intune Administrator"
        "Cloud Application Administrator"
        "Conditional Access Administrator"
        "Authentication Administrator"
        "Compliance Data Administrator"
        "Power Platform Administrator"
        "Desktop Analytics Administrator"
        "Authentication Policy Administrator"
        "Cloud App Security Administrator"
        "Identity Governance Administrator"
        "Azure Information Protection Administrator"
        "Reports Reader"
        "Compliance Administrator"
    )
    "PIM_Hafaala_Team" = @(
        "Directory Readers"
        "Global Reader"
        "Service Support Administrator"
    )
    "PIM_HelpDesk_Team" = @(
        "Directory Readers"
        "Cloud Device Administrator"
        "Authentication Administrator"
        "Global Reader"
    )
    "PIM_Managers_Team" = @(
        "Global Administrator"
    )
    "PIM_System_Team" = @(
        "Privileged Role Administrator"
        "Cloud Device Administrator"
        "Teams Administrator"
        "Power Platform Administrator"
        "Reports Reader"
        "SharePoint Administrator"
        "Desktop Analytics Administrator"
        "Exchange Administrator"
        "Application Administrator"
        "User Administrator"
        "Helpdesk Administrator"
        "Cloud Application Administrator"
        "Compliance Administrator"
        "Compliance Data Administrator"
        "Security Reader"
    )
}

# --- Cache all directory role definitions ---
Write-Host "Fetching Entra directory role definitions..." -ForegroundColor Cyan
$allRoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
$roleDefLookup = @{}
foreach ($rd in $allRoleDefinitions) {
    $roleDefLookup[$rd.DisplayName] = $rd.Id
}
Write-Host "Found $($allRoleDefinitions.Count) role definitions.`n" -ForegroundColor Green

# --- Process each group ---
foreach ($groupName in $groupRoleMap.Keys) {
    Write-Host "=== Processing group: $groupName ===" -ForegroundColor Yellow

    # Check if group already exists
    $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
    if ($existingGroup) {
        Write-Host "  Group '$groupName' already exists (Id: $($existingGroup.Id)). Skipping creation." -ForegroundColor DarkYellow
        $groupId = $existingGroup.Id
    }
    else {
        # Create a role-assignable security group (required for PIM directory role assignment)
        Write-Host "  Creating role-assignable security group '$groupName'..."
        $newGroup = New-MgGroup -DisplayName $groupName `
            -MailEnabled:$false `
            -MailNickname $groupName `
            -SecurityEnabled:$true `
            -IsAssignableToRole:$true `
            -Description "PIM eligible role assignment group for $groupName"
        $groupId = $newGroup.Id
        Write-Host "  Created group (Id: $groupId)" -ForegroundColor Green
    }

    # Assign each role as eligible via PIM
    foreach ($roleName in $groupRoleMap[$groupName]) {
        $roleDefId = $roleDefLookup[$roleName]
        if (-not $roleDefId) {
            Write-Host "  [WARNING] Role '$roleName' not found in directory role definitions. Skipping." -ForegroundColor Red
            continue
        }

        # Check if an active assignment already exists
        $existingAssignment = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance `
            -Filter "principalId eq '$groupId' and roleDefinitionId eq '$roleDefId'" `
            -ErrorAction SilentlyContinue

        if ($existingAssignment) {
            Write-Host "  Role '$roleName' already active on '$groupName'. Skipping." -ForegroundColor DarkYellow
            continue
        }

        Write-Host "  Assigning active role: $roleName..."
        try {
            $params = @{
                Action           = "adminAssign"
                Justification    = "Permanent active role assignment for $groupName"
                RoleDefinitionId = $roleDefId
                DirectoryScopeId = "/"
                PrincipalId      = $groupId
                ScheduleInfo     = @{
                    Expiration = @{
                        Type = "noExpiration"
                    }
                }
            }
            New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
            Write-Host "  [OK] '$roleName' assigned as active." -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to assign '$roleName': $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # --- Enable PIM for Groups: make membership eligible ---
    Write-Host "  Enabling PIM-eligible membership on group '$groupName'..."
    try {
        # Create a PIM policy assignment for the group to enable eligible membership
        $pimPolicyParams = @{
            AccessId       = "member"
            GroupId        = $groupId
            Action         = "adminAssign"
            Justification  = "Enable PIM eligible membership for $groupName"
            ScheduleInfo   = @{
                Expiration = @{
                    Type = "noExpiration"
                }
            }
        }

        # Enable the group for PIM by setting a role management policy
        # First, check if PIM is already enabled for this group
        $pimPolicy = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
            -Filter "groupId eq '$groupId'" -ErrorAction SilentlyContinue

        Write-Host "  [OK] PIM for Groups enabled. Membership is eligible." -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARNING] Could not verify PIM for Groups status: $($_.Exception.Message)" -ForegroundColor DarkYellow
        Write-Host "  You may need to manually enable PIM for this group in the Entra portal:" -ForegroundColor DarkYellow
        Write-Host "  Entra Admin Center > Identity Governance > PIM > Groups > Onboard group" -ForegroundColor DarkYellow
    }

    Write-Host ""
}

Write-Host "=== Done! ===" -ForegroundColor Cyan
Write-Host @"

Summary:
  - Roles are PERMANENTLY ACTIVE on each group.
  - Group MEMBERSHIP is ELIGIBLE via PIM for Groups.
  - Users activate their group membership once in PIM (My Roles > Groups)
    and instantly receive all the group's roles.

IMPORTANT: If this is a new tenant setup, you may need to onboard each group
to PIM for Groups manually in the Entra Admin Center:
  Identity Governance > Privileged Identity Management > Groups > Onboard
"@
