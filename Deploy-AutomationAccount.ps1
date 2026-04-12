<#
.SYNOPSIS
    Deploys the Azure Automation infrastructure for the expired-credentials
    runbook: Automation Account, modules, runbook, schedule, and variables.

.DESCRIPTION
    Run this script once from your local machine (or Cloud Shell) to provision
    everything. After deployment you still need to grant Microsoft Graph
    permissions to the Managed Identity (step shown at the end).

.PARAMETER SubscriptionId
    Azure subscription to deploy into.

.PARAMETER ResourceGroupName
    Resource group (created if it doesn't exist).

.PARAMETER Location
    Azure region. Default: eastus.

.PARAMETER AutomationAccountName
    Name for the Automation Account. Default: aa-credential-monitor.

.PARAMETER MailFrom
    Sender mailbox UPN (e.g. alerts@contoso.com).

.PARAMETER MailTo
    Comma-separated list of recipient addresses.

.PARAMETER WarningDays
    Look-ahead window in days. Default: 30.

.PARAMETER ScheduleTime
    Daily run time in HH:mm (UTC). Default: 08:00.

.EXAMPLE
    .\Deploy-AutomationAccount.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-credential-monitor" `
        -AutomationAccountName "aa-credential-monitor" `
        -MailFrom "alerts@contoso.com" `
        -MailTo "admin@contoso.com,security@contoso.com" `
        -ScheduleTime "08:00"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [string]$Location = 'eastus',

    [string]$AutomationAccountName = 'aa-credential-monitor',

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
$requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.Automation')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod ..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force
    }
    Import-Module $mod
}

# Login & set subscription
$context = Get-AzContext
if (-not $context) {
    Connect-AzAccount
}
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# ─────────────────────────────────────────────
# 1. Resource Group
# ─────────────────────────────────────────────
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating resource group $ResourceGroupName in $Location ..." -ForegroundColor Cyan
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}

# ─────────────────────────────────────────────
# 2. Automation Account (with system-assigned MI)
# ─────────────────────────────────────────────
$aa = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                              -Name $AutomationAccountName `
                              -ErrorAction SilentlyContinue

if (-not $aa) {
    Write-Host "Creating Automation Account $AutomationAccountName ..." -ForegroundColor Cyan
    $aa = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                                  -Name $AutomationAccountName `
                                  -Location $Location `
                                  -AssignSystemIdentity `
                                  -Plan Basic
}
else {
    Write-Host "Automation Account already exists." -ForegroundColor Green
}

$principalId = (Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                                         -Name $AutomationAccountName).Identity.PrincipalId
Write-Host "Managed Identity Principal ID: $principalId" -ForegroundColor Yellow

# ─────────────────────────────────────────────
# 3. Import PowerShell modules into the account
# ─────────────────────────────────────────────
$graphModules = @(
    @{ Name = 'Microsoft.Graph.Authentication';  Uri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication' }
    @{ Name = 'Microsoft.Graph.Applications';    Uri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Applications' }
    @{ Name = 'Microsoft.Graph.Users.Actions';   Uri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Users.Actions' }
)

foreach ($gm in $graphModules) {
    $existing = Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                       -AutomationAccountName $AutomationAccountName `
                                       -Name $gm.Name `
                                       -ErrorAction SilentlyContinue

    if ($existing -and $existing.ProvisioningState -eq 'Succeeded') {
        Write-Host "Module $($gm.Name) already imported." -ForegroundColor Green
        continue
    }

    Write-Host "Importing module $($gm.Name) (this may take a few minutes) ..." -ForegroundColor Cyan
    New-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                           -AutomationAccountName $AutomationAccountName `
                           -Name $gm.Name `
                           -ContentLinkUri $gm.Uri `
                           -RuntimeVersion '7.2' | Out-Null
}

# Wait for modules to finish provisioning
Write-Host "Waiting for module provisioning ..." -ForegroundColor Cyan
foreach ($gm in $graphModules) {
    $attempts = 0
    do {
        Start-Sleep -Seconds 15
        $modState = (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                            -AutomationAccountName $AutomationAccountName `
                                            -Name $gm.Name).ProvisioningState
        $attempts++
        Write-Host "  $($gm.Name): $modState (attempt $attempts)" -ForegroundColor Gray
    } while ($modState -notin @('Succeeded', 'Failed') -and $attempts -lt 40)

    if ($modState -eq 'Failed') {
        Write-Error "Module $($gm.Name) failed to import!"
    }
}

# ─────────────────────────────────────────────
# 4. Automation Variables
# ─────────────────────────────────────────────
$variables = @(
    @{ Name = 'MailFrom';     Value = $MailFrom;     Encrypted = $false }
    @{ Name = 'MailTo';       Value = $MailTo;        Encrypted = $false }
    @{ Name = 'WarningDays';  Value = $WarningDays;   Encrypted = $false }
)

foreach ($v in $variables) {
    $existing = Get-AzAutomationVariable -ResourceGroupName $ResourceGroupName `
                                         -AutomationAccountName $AutomationAccountName `
                                         -Name $v.Name `
                                         -ErrorAction SilentlyContinue
    if ($existing) {
        Set-AzAutomationVariable -ResourceGroupName $ResourceGroupName `
                                 -AutomationAccountName $AutomationAccountName `
                                 -Name $v.Name `
                                 -Value $v.Value `
                                 -Encrypted $v.Encrypted | Out-Null
        Write-Host "Updated variable: $($v.Name)" -ForegroundColor Green
    }
    else {
        New-AzAutomationVariable -ResourceGroupName $ResourceGroupName `
                                 -AutomationAccountName $AutomationAccountName `
                                 -Name $v.Name `
                                 -Value $v.Value `
                                 -Encrypted $v.Encrypted | Out-Null
        Write-Host "Created variable: $($v.Name)" -ForegroundColor Green
    }
}

# ─────────────────────────────────────────────
# 5. Import the Runbook
# ─────────────────────────────────────────────
$runbookName = 'Check-ExpiredAppCredentials'
$runbookPath = Join-Path $PSScriptRoot 'Runbook-ExpiredAppCredentials.ps1'

if (-not (Test-Path $runbookPath)) {
    Write-Error "Runbook script not found at $runbookPath. Place it next to this deployment script."
}

Write-Host "Importing runbook $runbookName ..." -ForegroundColor Cyan
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                           -AutomationAccountName $AutomationAccountName `
                           -Name $runbookName `
                           -Path $runbookPath `
                           -Type PowerShell `
                           -RuntimeVersion '7.2' `
                           -Force | Out-Null

Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                            -AutomationAccountName $AutomationAccountName `
                            -Name $runbookName | Out-Null

Write-Host "Runbook published." -ForegroundColor Green

# ─────────────────────────────────────────────
# 6. Create a daily schedule and link it
# ─────────────────────────────────────────────
$scheduleName = 'Daily-CredentialCheck'

$startTime = [DateTime]::ParseExact($ScheduleTime, 'HH:mm', $null)
$startDate = [DateTime]::UtcNow.Date.AddDays(1).Add($startTime.TimeOfDay)

$existing = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                                     -AutomationAccountName $AutomationAccountName `
                                     -Name $scheduleName `
                                     -ErrorAction SilentlyContinue

if (-not $existing) {
    Write-Host "Creating daily schedule at $ScheduleTime UTC ..." -ForegroundColor Cyan
    New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                             -AutomationAccountName $AutomationAccountName `
                             -Name $scheduleName `
                             -StartTime $startDate `
                             -DayInterval 1 `
                             -TimeZone 'UTC' | Out-Null
}
else {
    Write-Host "Schedule '$scheduleName' already exists." -ForegroundColor Green
}

# Link schedule → runbook
Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName `
                                      -AutomationAccountName $AutomationAccountName `
                                      -RunbookName $runbookName `
                                      -ScheduleName $scheduleName `
                                      -ErrorAction SilentlyContinue | Out-Null

Write-Host "Schedule linked to runbook." -ForegroundColor Green

# ─────────────────────────────────────────────
# 7. Instructions for granting Graph permissions
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host " MANUAL STEP REQUIRED – Grant Graph permissions to Managed Identity" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow

@"
@"

Run the following in a PowerShell session with Global Admin / Privileged Role Admin rights:

    Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All'

    `$miPrincipalId = '$principalId'
    `$graphSp       = Get-MgServicePrincipal -Filter `"appId eq '00000003-0000-0000-c000-000000000000'`"

    # Application.Read.All
    `$appReadRole = `$graphSp.AppRoles | Where-Object Value -eq 'Application.Read.All'
    New-MgServicePrincipalAppRoleAssignment ``
        -ServicePrincipalId `$miPrincipalId ``
        -PrincipalId        `$miPrincipalId ``
        -ResourceId         `$graphSp.Id ``
        -AppRoleId          `$appReadRole.Id

    # Mail.Send
    `$mailSendRole = `$graphSp.AppRoles | Where-Object Value -eq 'Mail.Send'
    New-MgServicePrincipalAppRoleAssignment ``
        -ServicePrincipalId `$miPrincipalId ``
        -PrincipalId        `$miPrincipalId ``
        -ResourceId         `$graphSp.Id ``
        -AppRoleId          `$mailSendRole.Id
"@