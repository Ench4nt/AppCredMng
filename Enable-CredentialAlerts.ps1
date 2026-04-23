<#
.SYNOPSIS
    Enables the Expired App Credential Alerts feature on an existing
    Azure Automation Account.

.DESCRIPTION
    Imports the required Graph modules, creates Automation Variables,
    publishes the runbook, and creates a daily schedule. Run this after
    Deploy-AutomationAccount.ps1 has created the Automation Account.

    At the end, prints the Graph permissions you need to grant to the
    Managed Identity.

.PARAMETER ResourceGroupName
    Resource group containing the Automation Account.

.PARAMETER AutomationAccountName
    Name of the existing Automation Account.

.PARAMETER MailFrom
    Sender mailbox UPN (e.g. alerts@contoso.com). Must be a valid mailbox.

.PARAMETER MailTo
    Comma-separated list of recipient email addresses.

.PARAMETER WarningDays
    Number of days to look ahead for soon-to-expire credentials. Default: 30.

.PARAMETER ScheduleTime
    Daily run time in HH:mm (UTC). Default: 08:00.

.EXAMPLE
    .\Enable-CredentialAlerts.ps1 `
        -ResourceGroupName "rg-entra-monitor" `
        -AutomationAccountName "aa-entra-monitor" `
        -MailFrom "alerts@contoso.com" `
        -MailTo "admin@contoso.com,security@contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$AutomationAccountName,

    [Parameter(Mandatory)]
    [string]$MailFrom,

    [Parameter(Mandatory)]
    [string]$MailTo,

    [int]$WarningDays = 30,

    [string]$ScheduleTime = '08:00'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# 0. Prerequisites
# ─────────────────────────────────────────────
foreach ($mod in @('Az.Accounts', 'Az.Automation')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $mod
}

$context = Get-AzContext
if (-not $context) { Connect-AzAccount }

# Verify the Automation Account exists
$aa = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                              -Name $AutomationAccountName `
                              -ErrorAction Stop
$principalId = $aa.Identity.PrincipalId

if (-not $principalId) {
    Write-Error "Automation Account '$AutomationAccountName' does not have a Managed Identity. Run Deploy-AutomationAccount.ps1 first."
}

Write-Host "Enabling Credential Alerts on '$AutomationAccountName' ..." -ForegroundColor Cyan
Write-Host "Managed Identity: $principalId" -ForegroundColor Gray

# ─────────────────────────────────────────────
# 1. Import required Graph modules
# ─────────────────────────────────────────────
$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Applications';  Uri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Applications/2.25.0' }
    @{ Name = 'Microsoft.Graph.Users.Actions'; Uri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Users.Actions/2.25.0' }
)

$modulesToWait = [System.Collections.Generic.List[string]]::new()

foreach ($gm in $requiredModules) {
    $alreadyImported = $false
    try {
        $existing = Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                           -AutomationAccountName $AutomationAccountName `
                                           -Name $gm.Name
        if ($existing -and $existing.ProvisioningState -eq 'Succeeded') {
            Write-Host "  Module $($gm.Name) already imported." -ForegroundColor Green
            $alreadyImported = $true
        }
    }
    catch { }

    if (-not $alreadyImported) {
        try {
            Write-Host "  Importing $($gm.Name) ..." -ForegroundColor Cyan
            New-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                   -AutomationAccountName $AutomationAccountName `
                                   -Name $gm.Name `
                                   -ContentLinkUri $gm.Uri | Out-Null
            $modulesToWait.Add($gm.Name)
        }
        catch {
            Write-Error "Failed to import $($gm.Name): $_"
            throw
        }
    }
}

if ($modulesToWait.Count -gt 0) {
    Write-Host "Waiting for module provisioning ..." -ForegroundColor Cyan
    foreach ($modName in $modulesToWait) {
        $attempts = 0; $modState = 'Unknown'
        do {
            Start-Sleep -Seconds 15
            try {
                $modState = (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                                    -AutomationAccountName $AutomationAccountName `
                                                    -Name $modName).ProvisioningState
            }
            catch { $modState = 'NotFound' }
            $attempts++
            Write-Host "    ${modName}: $modState (attempt $attempts)" -ForegroundColor Gray
        } while ($modState -notin @('Succeeded', 'Failed') -and $attempts -lt 40)
        if ($modState -eq 'Failed') { Write-Error "Module $modName failed to import!" }
        elseif ($modState -eq 'Succeeded') { Write-Host "    ${modName}: Ready." -ForegroundColor Green }
    }
}

# ─────────────────────────────────────────────
# 2. Automation Variables
# ─────────────────────────────────────────────
$variables = @(
    @{ Name = 'MailFrom';    Value = $MailFrom;    Encrypted = $false }
    @{ Name = 'MailTo';      Value = $MailTo;      Encrypted = $false }
    @{ Name = 'WarningDays'; Value = $WarningDays; Encrypted = $false }
)

foreach ($v in $variables) {
    $existing = Get-AzAutomationVariable -ResourceGroupName $ResourceGroupName `
                                         -AutomationAccountName $AutomationAccountName `
                                         -Name $v.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Set-AzAutomationVariable -ResourceGroupName $ResourceGroupName `
                                 -AutomationAccountName $AutomationAccountName `
                                 -Name $v.Name -Value $v.Value -Encrypted $v.Encrypted | Out-Null
        Write-Host "  Updated variable: $($v.Name)" -ForegroundColor Green
    }
    else {
        New-AzAutomationVariable -ResourceGroupName $ResourceGroupName `
                                 -AutomationAccountName $AutomationAccountName `
                                 -Name $v.Name -Value $v.Value -Encrypted $v.Encrypted | Out-Null
        Write-Host "  Created variable: $($v.Name)" -ForegroundColor Green
    }
}

# ─────────────────────────────────────────────
# 3. Import and publish runbook
# ─────────────────────────────────────────────
$runbookName = 'Check-ExpiredAppCredentials'
$runbookPath = Join-Path $PSScriptRoot 'Runbook-ExpiredAppCredentials.ps1'

if (-not (Test-Path $runbookPath)) {
    Write-Error "Runbook not found at $runbookPath. Place it next to this script."
}

Write-Host "  Importing runbook $runbookName ..." -ForegroundColor Cyan
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                           -AutomationAccountName $AutomationAccountName `
                           -Name $runbookName -Path $runbookPath `
                           -Type PowerShell -Force | Out-Null

Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                            -AutomationAccountName $AutomationAccountName `
                            -Name $runbookName | Out-Null
Write-Host "  Runbook published." -ForegroundColor Green

# ─────────────────────────────────────────────
# 4. Create daily schedule
# ─────────────────────────────────────────────
$scheduleName = 'Daily-CredentialCheck'
$startTime = [DateTime]::Parse($ScheduleTime)
$startDate = [DateTime]::UtcNow.Date.AddDays(1).Add($startTime.TimeOfDay)

$existing = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                                     -AutomationAccountName $AutomationAccountName `
                                     -Name $scheduleName -ErrorAction SilentlyContinue

if (-not $existing) {
    Write-Host "  Creating daily schedule at $ScheduleTime UTC ..." -ForegroundColor Cyan
    New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                             -AutomationAccountName $AutomationAccountName `
                             -Name $scheduleName -StartTime $startDate `
                             -DayInterval 1 -TimeZone 'UTC' | Out-Null
}
else {
    Write-Host "  Schedule '$scheduleName' already exists." -ForegroundColor Green
}

Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName `
                                      -AutomationAccountName $AutomationAccountName `
                                      -RunbookName $runbookName `
                                      -ScheduleName $scheduleName `
                                      -ErrorAction SilentlyContinue | Out-Null
Write-Host "  Schedule linked to runbook." -ForegroundColor Green

# ─────────────────────────────────────────────
# 5. Required Graph permissions
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host " Credential Alerts Enabled!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "REQUIRED: Grant these Graph permissions to the Managed Identity:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All'" -ForegroundColor White
Write-Host "  `$miPrincipalId = '$principalId'" -ForegroundColor White
Write-Host "  `$graphSp = Get-MgServicePrincipal -Filter `"appId eq '00000003-0000-0000-c000-000000000000'`"" -ForegroundColor White
Write-Host ""
Write-Host "  `$permissions = @('Application.Read.All', 'Mail.Send')" -ForegroundColor White
Write-Host "  foreach (`$perm in `$permissions) {" -ForegroundColor White
Write-Host "      `$role = `$graphSp.AppRoles | Where-Object Value -eq `$perm" -ForegroundColor White
Write-Host "      New-MgServicePrincipalAppRoleAssignment ``" -ForegroundColor White
Write-Host "          -ServicePrincipalId `$miPrincipalId ``" -ForegroundColor White
Write-Host "          -PrincipalId `$miPrincipalId ``" -ForegroundColor White
Write-Host "          -ResourceId `$graphSp.Id ``" -ForegroundColor White
Write-Host "          -AppRoleId `$role.Id" -ForegroundColor White
Write-Host "  }" -ForegroundColor White
Write-Host ""
