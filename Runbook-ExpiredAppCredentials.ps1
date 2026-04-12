<#
.SYNOPSIS
    Azure Automation Runbook – reports app registrations with expired or
    soon-to-expire secrets and certificates via email.

.DESCRIPTION
    Designed to run unattended in an Azure Automation Account using a
    System-Assigned Managed Identity. Configuration is read from
    Automation Variables so nothing is hard-coded.

    Required Automation Variables (create in the Automation Account):
        MailFrom     (string)  – sender mailbox UPN, e.g. alerts@contoso.com
        MailTo       (string)  – comma-separated recipients
        WarningDays  (int)     – look-ahead window (default: 30)

    Required Graph API permissions on the Managed Identity:
        Application.Read.All
        Mail.Send

    Required Automation Account modules (PowerShell 7.2 runtime):
        Microsoft.Graph.Authentication
        Microsoft.Graph.Applications
        Microsoft.Graph.Users.Actions
#>

param(
    [int]$WarningDays = 30
)

$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# 1. Read configuration from Automation Variables
# ─────────────────────────────────────────────
try {
    $mailFrom    = [string](Get-AutomationVariable -Name 'MailFrom')
    $mailToRaw   = [string](Get-AutomationVariable -Name 'MailTo')
    $mailTo      = @($mailToRaw -split '\s*,\s*' | Where-Object { $_ -ne '' })
    $WarningDays = Get-AutomationVariable -Name 'WarningDays' -ErrorAction SilentlyContinue
    if (-not $WarningDays) { $WarningDays = 30 }
}
catch {
    Write-Error "Failed to read Automation Variables. Ensure MailFrom and MailTo are defined. $_"
    throw
}

Write-Output "Config loaded – From: $mailFrom | To: $($mailTo -join ', ') | Warning window: $WarningDays days"

# ─────────────────────────────────────────────
# 2. Connect to Microsoft Graph via Managed Identity
# ─────────────────────────────────────────────
try {
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
    Write-Output "Connected to Microsoft Graph using Managed Identity."
}
catch {
    Write-Error "Graph authentication failed. Ensure the Managed Identity has the required permissions. $_"
    throw
}

# ─────────────────────────────────────────────
# 3. Retrieve all app registrations
# ─────────────────────────────────────────────
Write-Output "Fetching app registrations ..."
$apps = Get-MgApplication -All -Property Id, AppId, DisplayName, PasswordCredentials, KeyCredentials
Write-Output "Found $($apps.Count) app registration(s)."

# ─────────────────────────────────────────────
# 4. Inspect credentials
# ─────────────────────────────────────────────
$now           = [DateTime]::UtcNow
$warningCutoff = $now.AddDays($WarningDays)
$findings      = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($app in $apps) {

    foreach ($secret in $app.PasswordCredentials) {
        if ($null -eq $secret.EndDateTime) { continue }
        $endDate = $secret.EndDateTime.ToUniversalTime()

        if ($endDate -le $warningCutoff) {
            $findings.Add([PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId   = $app.AppId
                ObjectId        = $app.Id
                CredentialType  = 'Client Secret'
                KeyId           = $secret.KeyId
                DisplayName     = $secret.DisplayName
                EndDate         = $endDate
                DaysRemaining   = [Math]::Floor(($endDate - $now).TotalDays)
                Status          = if ($endDate -le $now) { 'Expired' } else { 'Expiring Soon' }
            })
        }
    }

    foreach ($cert in $app.KeyCredentials) {
        if ($null -eq $cert.EndDateTime) { continue }
        $endDate = $cert.EndDateTime.ToUniversalTime()

        if ($endDate -le $warningCutoff) {
            $findings.Add([PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId   = $app.AppId
                ObjectId        = $app.Id
                CredentialType  = 'Certificate'
                KeyId           = $cert.KeyId
                DisplayName     = $cert.DisplayName
                EndDate         = $endDate
                DaysRemaining   = [Math]::Floor(($endDate - $now).TotalDays)
                Status          = if ($endDate -le $now) { 'Expired' } else { 'Expiring Soon' }
            })
        }
    }
}

Write-Output "Found $($findings.Count) expired or expiring credential(s)."

if ($findings.Count -eq 0) {
    Write-Output "Nothing to report. Exiting."
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    return
}

# ─────────────────────────────────────────────
# 5. Build HTML email
# ─────────────────────────────────────────────
$expiredCount  = @($findings | Where-Object Status -eq 'Expired').Count
$expiringCount = @($findings | Where-Object Status -eq 'Expiring Soon').Count

$tableRows = ($findings | Sort-Object Status, EndDate | ForEach-Object {
    $rowColor = if ($_.Status -eq 'Expired') { '#fdd' } else { '#fff8e1' }
    @"
    <tr style="background-color:$rowColor;">
        <td>$($_.ApplicationName)</td>
        <td><code>$($_.ApplicationId)</code></td>
        <td>$($_.CredentialType)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.EndDate.ToString('yyyy-MM-dd'))</td>
        <td>$($_.DaysRemaining)</td>
        <td><strong>$($_.Status)</strong></td>
    </tr>
"@
}) -join "`n"

$htmlBody = @"
<!DOCTYPE html>
<html>
<head>
<style>
    body   { font-family: Segoe UI, Arial, sans-serif; color: #333; }
    h2     { color: #c0392b; }
    table  { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 14px; }
    th     { background-color: #2c3e50; color: #fff; }
    .note  { font-size: 13px; color: #888; margin-top: 16px; }
</style>
</head>
<body>
    <h2>&#9888; App Registration Credential Alert</h2>
    <p>
        <strong style="color:red;">$expiredCount</strong> expired &nbsp;|&nbsp;
        <strong style="color:orange;">$expiringCount</strong> expiring within $WarningDays days
    </p>
    <table>
        <tr>
            <th>Application</th>
            <th>App (Client) ID</th>
            <th>Type</th>
            <th>Credential Name</th>
            <th>Expiry Date (UTC)</th>
            <th>Days Remaining</th>
            <th>Status</th>
        </tr>
        $tableRows
    </table>
    <p class="note">
        Generated on $($now.ToString('yyyy-MM-dd HH:mm:ss')) UTC by Azure Automation.
    </p>
</body>
</html>
"@

# ─────────────────────────────────────────────
# 6. Send alert email via Microsoft Graph
# ─────────────────────────────────────────────
$subject = "App Credential Alert – $expiredCount expired, $expiringCount expiring"

$toRecipients = @($mailTo | ForEach-Object {
    @{ EmailAddress = @{ Address = $_ } }
})

$mailBody = @{
    Message = @{
        Subject      = $subject
        Body         = @{ ContentType = 'HTML'; Content = $htmlBody }
        ToRecipients = $toRecipients
    }
}

Send-MgUserMail -UserId $mailFrom -BodyParameter $mailBody -ErrorAction Stop
Write-Output "Alert email sent to $($mailTo -join ', ')."

# ─────────────────────────────────────────────
# 7. Output summary to job log
# ─────────────────────────────────────────────
$findings | Format-Table ApplicationName, CredentialType, DisplayName, EndDate, DaysRemaining, Status -AutoSize | Out-String | Write-Output

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Write-Output "Runbook completed successfully."
