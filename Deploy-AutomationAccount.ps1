<#
.SYNOPSIS
    Deploys a generic Azure Automation Account with a System-Assigned
    Managed Identity and the base Microsoft Graph Authentication module.

.DESCRIPTION
    Run this script once to provision the Automation Account infrastructure.
    After this, use feature-specific scripts to enable individual runbooks:
      - Enable-CredentialAlerts.ps1  (expired app credential monitoring)
      - Enable-CAAudit.ps1          (Conditional Access policy audit)

.PARAMETER SubscriptionId
    Azure subscription to deploy into.

.PARAMETER ResourceGroupName
    Resource group (created if it doesn't exist).

.PARAMETER Location
    Azure region. Default: eastus.

.PARAMETER AutomationAccountName
    Name for the Automation Account. Default: aa-entra-monitor.

.EXAMPLE
    .\Deploy-AutomationAccount.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-entra-monitor" `
        -Location "westeurope" `
        -AutomationAccountName "aa-entra-monitor"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [string]$Location = 'eastus',

    [string]$AutomationAccountName = 'aa-entra-monitor'
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
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $mod
}

$context = Get-AzContext
if (-not $context) { Connect-AzAccount }
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# ─────────────────────────────────────────────
# 1. Resource Group
# ─────────────────────────────────────────────
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating resource group $ResourceGroupName in $Location ..." -ForegroundColor Cyan
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}
else {
    Write-Host "Resource group '$ResourceGroupName' already exists." -ForegroundColor Green
}

# ─────────────────────────────────────────────
# 2. Automation Account (with system-assigned MI)
# ─────────────────────────────────────────────
$aa = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                              -Name $AutomationAccountName `
                              -ErrorAction SilentlyContinue

if (-not $aa) {
    Write-Host "Creating Automation Account $AutomationAccountName ..." -ForegroundColor Cyan
    New-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                            -Name $AutomationAccountName `
                            -Location $Location `
                            -AssignSystemIdentity `
                            -Plan Basic | Out-Null
}
else {
    Write-Host "Automation Account '$AutomationAccountName' already exists." -ForegroundColor Green
}

$principalId = (Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                                         -Name $AutomationAccountName).Identity.PrincipalId

# ─────────────────────────────────────────────
# 3. Import base Microsoft Graph Authentication module
# ─────────────────────────────────────────────
$baseModule = @{ Name = 'Microsoft.Graph.Authentication'; Uri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/2.25.0' }

$alreadyImported = $false
try {
    $existing = Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                       -AutomationAccountName $AutomationAccountName `
                                       -Name $baseModule.Name
    if ($existing -and $existing.ProvisioningState -eq 'Succeeded') {
        Write-Host "Module $($baseModule.Name) already imported." -ForegroundColor Green
        $alreadyImported = $true
    }
}
catch { }

if (-not $alreadyImported) {
    Write-Host "Importing $($baseModule.Name) ..." -ForegroundColor Cyan
    New-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                           -AutomationAccountName $AutomationAccountName `
                           -Name $baseModule.Name `
                           -ContentLinkUri $baseModule.Uri | Out-Null

    $attempts = 0
    do {
        Start-Sleep -Seconds 15
        try {
            $modState = (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                                -AutomationAccountName $AutomationAccountName `
                                                -Name $baseModule.Name).ProvisioningState
        }
        catch { $modState = 'NotFound' }
        $attempts++
        Write-Host "  $($baseModule.Name): $modState (attempt $attempts)" -ForegroundColor Gray
    } while ($modState -notin @('Succeeded', 'Failed') -and $attempts -lt 40)

    if ($modState -eq 'Failed') { Write-Error "Base module failed to import!" }
}

# ─────────────────────────────────────────────
# 4. Summary
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host " Automation Account Ready" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  Resource Group:      $ResourceGroupName" -ForegroundColor White
Write-Host "  Automation Account:  $AutomationAccountName" -ForegroundColor White
Write-Host "  Managed Identity:    $principalId" -ForegroundColor White
Write-Host ""
Write-Host "Next steps — enable features by running:" -ForegroundColor Yellow
Write-Host "  .\Enable-CredentialAlerts.ps1 -ResourceGroupName '$ResourceGroupName' -AutomationAccountName '$AutomationAccountName' ..." -ForegroundColor Cyan
Write-Host "  .\Enable-CAAudit.ps1          -ResourceGroupName '$ResourceGroupName' -AutomationAccountName '$AutomationAccountName' ..." -ForegroundColor Cyan
Write-Host ""