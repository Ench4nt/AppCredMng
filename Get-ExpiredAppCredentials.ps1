<#
.SYNOPSIS
    Finds Azure AD / Entra ID app registrations with expired (or soon-to-expire)
    secrets and certificates, then sends an alert email via Microsoft Graph.

.DESCRIPTION
    - Connects to Microsoft Graph using app-only or delegated auth.
    - Retrieves every app registration and inspects its password credentials
      (client secrets) and key credentials (certificates).
    - Flags credentials that are already expired or will expire within a
      configurable warning window.
    - Sends a single HTML-formatted alert email summarising the findings.

.PARAMETER TenantId
    Azure AD / Entra ID tenant ID.

.PARAMETER ClientId
    Application (client) ID used to authenticate to Microsoft Graph.

.PARAMETER ClientSecret
    Client secret for app-only authentication. Omit to use interactive/delegated auth.

.PARAMETER WarningDays
    Number of days to look ahead for soon-to-expire credentials. Default: 30.

.PARAMETER MailFrom
    UPN or object-id of the mailbox (or shared mailbox) used to send the alert.
    Requires Mail.Send permission.

.PARAMETER MailTo
    One or more recipient email addresses (comma-separated).

.PARAMETER SmtpServer
    (Optional) If set, sends via SMTP relay instead of Microsoft Graph.

.PARAMETER SmtpPort
    SMTP port. Default: 587.

.PARAMETER SmtpCredential
    PSCredential for SMTP authentication.

.PARAMETER UseSsl
    Use TLS for SMTP. Default: $true.

.EXAMPLE
    # App-only auth + Graph mail
    .\Get-ExpiredAppCredentials.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret "your-secret" `
        -MailFrom "alerts@contoso.com" `
        -MailTo "admin@contoso.com","security@contoso.com" `
        -WarningDays 30

.EXAMPLE
    # Interactive auth + SMTP relay
    .\Get-ExpiredAppCredentials.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -MailFrom "alerts@contoso.com" `
        -MailTo "admin@contoso.com" `
        -SmtpServer "smtp.office365.com" `
        -SmtpCredential (Get-Credential)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [string]$ClientSecret,

    [int]$WarningDays = 30,

    [Parameter(Mandatory)]
    [string]$MailFrom,

    [Parameter(Mandatory)]
    [string[]]$MailTo,

    [string]$SmtpServer,

    [int]$SmtpPort = 587,

    [PSCredential]$SmtpCredential,

    [bool]$UseSsl = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# 1. Ensure the Microsoft Graph module is loaded
# ─────────────────────────────────────────────
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Users.Actions'      # for Send-MgUserMail
)

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing module $mod ..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $mod -ErrorAction Stop
}

# ─────────────────────────────────────────────
# 2. Connect to Microsoft Graph
# ─────────────────────────────────────────────
$graphScopes = @('Application.Read.All', 'Mail.Send')

if ($ClientSecret) {
    # App-only (client credentials) flow
    $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $credential   = [PSCredential]::new($ClientId, $secureSecret)

    Connect-MgGraph -TenantId $TenantId `
                    -ClientSecretCredential $credential `
                    -NoWelcome
    Write-Host "Connected to Graph (app-only) for tenant $TenantId" -ForegroundColor Green
}
else {
    # Delegated / interactive flow
    Connect-MgGraph -TenantId $TenantId `
                    -ClientId $ClientId `
                    -Scopes $graphScopes `
                    -NoWelcome
    Write-Host "Connected to Graph (delegated) for tenant $TenantId" -ForegroundColor Green
}

# ─────────────────────────────────────────────
# 3. Retrieve all app registrations
# ─────────────────────────────────────────────
Write-Host "Fetching app registrations ..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property Id, AppId, DisplayName, PasswordCredentials, KeyCredentials `
        -ErrorAction Stop

Write-Host "Found $($apps.Count) app registration(s)." -ForegroundColor Cyan

# ─────────────────────────────────────────────
# 4. Inspect credentials and build a report
# ─────────────────────────────────────────────
$now           = [DateTime]::UtcNow
$warningCutoff = $now.AddDays($WarningDays)
$findings      = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($app in $apps) {

    # --- Password credentials (client secrets) ---
    foreach ($secret in $app.PasswordCredentials) {
        if ($null -eq $secret.EndDateTime) { continue }

        $endDate = $secret.EndDateTime.ToUniversalTime()

        if ($endDate -le $warningCutoff) {
            $status = if ($endDate -le $now) { 'Expired' } else { 'Expiring Soon' }

            $findings.Add([PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId   = $app.AppId
                ObjectId        = $app.Id
                CredentialType  = 'Client Secret'
                KeyId           = $secret.KeyId
                DisplayName     = $secret.DisplayName
                StartDate       = $secret.StartDateTime
                EndDate         = $endDate
                DaysRemaining   = [Math]::Floor(($endDate - $now).TotalDays)
                Status          = $status
            })
        }
    }

    # --- Key credentials (certificates) ---
    foreach ($cert in $app.KeyCredentials) {
        if ($null -eq $cert.EndDateTime) { continue }

        $endDate = $cert.EndDateTime.ToUniversalTime()

        if ($endDate -le $warningCutoff) {
            $status = if ($endDate -le $now) { 'Expired' } else { 'Expiring Soon' }

            $findings.Add([PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId   = $app.AppId
                ObjectId        = $app.Id
                CredentialType  = 'Certificate'
                KeyId           = $cert.KeyId
                DisplayName     = $cert.DisplayName
                StartDate       = $cert.StartDateTime
                EndDate         = $endDate
                DaysRemaining   = [Math]::Floor(($endDate - $now).TotalDays)
                Status          = $status
            })
        }
    }
}

Write-Host "Found $($findings.Count) expired / expiring credential(s)." -ForegroundColor Yellow

if ($findings.Count -eq 0) {
    Write-Host "No expired or soon-to-expire credentials found. No email will be sent." -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    return
}

# ─────────────────────────────────────────────
# 5. Build the HTML email body
# ─────────────────────────────────────────────
$expiredCount  = ($findings | Where-Object Status -eq 'Expired').Count
$expiringCount = ($findings | Where-Object Status -eq 'Expiring Soon').Count

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
        The following credentials require attention in tenant <strong>$TenantId</strong>:<br/>
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
        Generated on $($now.ToString('yyyy-MM-dd HH:mm:ss')) UTC by
        <em>Get-ExpiredAppCredentials.ps1</em>.
    </p>
</body>
</html>
"@

# ─────────────────────────────────────────────
# 6. Send the alert email
# ─────────────────────────────────────────────
$subject = "[$TenantId] App Registration Credential Alert - $expiredCount expired, $expiringCount expiring"

if ($SmtpServer) {
    # ── SMTP relay ──
    $mailParams = @{
        From       = $MailFrom
        To         = $MailTo
        Subject    = $subject
        Body       = $htmlBody
        BodyAsHtml = $true
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
        UseSsl     = $UseSsl
    }
    if ($SmtpCredential) {
        $mailParams['Credential'] = $SmtpCredential
    }

    Send-MailMessage @mailParams -WarningAction SilentlyContinue
    Write-Host "Alert email sent via SMTP ($SmtpServer) to $($MailTo -join ', ')." -ForegroundColor Green
}
else {
    # ── Microsoft Graph (Send-MgUserMail) ──
    $toRecipients = $MailTo | ForEach-Object {
        @{ EmailAddress = @{ Address = $_ } }
    }

    $message = @{
        Subject      = $subject
        Body         = @{
            ContentType = 'HTML'
            Content     = $htmlBody
        }
        ToRecipients = $toRecipients
    }

    Send-MgUserMail -UserId $MailFrom -Message $message -ErrorAction Stop
    Write-Host "Alert email sent via Microsoft Graph from $MailFrom to $($MailTo -join ', ')." -ForegroundColor Green
}

# ─────────────────────────────────────────────
# 7. Console summary & cleanup
# ─────────────────────────────────────────────
$findings | Format-Table ApplicationName, CredentialType, DisplayName, EndDate, DaysRemaining, Status -AutoSize

Disconnect-MgGraph | Out-Null
Write-Host "Done." -ForegroundColor Green
