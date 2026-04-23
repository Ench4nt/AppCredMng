<#
.SYNOPSIS
    Audits Entra ID Conditional Access policies for security gaps, hygiene
    issues, and organizational best practices.

.DESCRIPTION
    Connects to Microsoft Graph and performs a comprehensive audit of all
    Conditional Access policies in the tenant with 27 checks across security
    gaps, governance, and policy hygiene.

.PARAMETER TenantId
    Azure AD / Entra ID tenant ID. Optional for interactive auth.

.PARAMETER ClientId
    Application (client) ID. Optional for interactive auth.

.PARAMETER ClientSecret
    Client secret for app-only auth. Omit for interactive/delegated auth.

.PARAMETER MailFrom
    Sender mailbox UPN. Required only if sending email.

.PARAMETER MailTo
    Recipient email addresses. Required only if sending email.

.PARAMETER SignInLookbackDays
    Days of sign-in logs to check. Default: 30.

.PARAMETER ReportOnlyThresholdDays
    Flag report-only policies older than this. Default: 60.

.PARAMETER DisabledThresholdDays
    Flag disabled policies older than this. Default: 30.

.PARAMETER LargeGroupThreshold
    Flag exclusion groups larger than this. Default: 50.

.PARAMETER OutputPath
    Optional file path to save the HTML report.

.EXAMPLE
    # Interactive auth using current user context
    .\Audit-ConditionalAccessPolicies.ps1 -OutputPath ".\CA-Audit-Report.html"

.EXAMPLE
    # App-only auth with client secret
    .\Audit-ConditionalAccessPolicies.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret "your-secret" `
        -MailFrom "alerts@contoso.com" `
        -MailTo "admin@contoso.com","security@contoso.com"
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$MailFrom,
    [string[]]$MailTo,
    [int]$SignInLookbackDays = 30,
    [int]$ReportOnlyThresholdDays = 60,
    [int]$DisabledThresholdDays = 30,
    [int]$LargeGroupThreshold = 50,
    [string]$OutputPath,
    [switch]$SkipAuth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# 1. Ensure required modules
# ─────────────────────────────────────────────
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Reports',
    'Microsoft.Graph.Users.Actions'
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
$graphScopes = @(
    'Policy.Read.All',
    'AuditLog.Read.All',
    'Group.Read.All',
    'User.Read.All',
    'Application.Read.All',
    'Mail.Send'
)

if ($SkipAuth) {
    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "No existing Microsoft Graph session found. Run Connect-MgGraph first or remove -SkipAuth."
    }
    Write-Host "Using existing Graph session ($($ctx.Account))." -ForegroundColor Green
}
elseif ($ClientSecret -and $ClientId -and $TenantId) {
    $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $credential   = [PSCredential]::new($ClientId, $secureSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome
    Write-Host "Connected to Graph (app-only) for tenant $TenantId" -ForegroundColor Green
}
elseif ($TenantId -and $ClientId) {
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Scopes $graphScopes -NoWelcome
    Write-Host "Connected to Graph (delegated) for tenant $TenantId" -ForegroundColor Green
}
else {
    Connect-MgGraph -Scopes $graphScopes -NoWelcome
    Write-Host "Connected to Graph (interactive) using current user context." -ForegroundColor Green
}

# ─────────────────────────────────────────────
# 3. Fetch all data
# ─────────────────────────────────────────────
Write-Host "Fetching Conditional Access policies ..." -ForegroundColor Cyan
$policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
Write-Host "Found $($policies.Count) CA policy(ies)." -ForegroundColor Cyan

Write-Host "Fetching named locations ..." -ForegroundColor Cyan
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
Write-Host "Found $($namedLocations.Count) named location(s)." -ForegroundColor Cyan

$adminRoleIds = @(
    '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'  # SharePoint Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'  # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'  # Cloud Application Administrator
    '966707d0-3269-4727-9be2-8c3a10f19b9d'  # Password Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
    'e6d1a23a-da11-4be4-9570-befc86d067a7'  # Compliance Administrator
    '3a2c62db-5318-420d-8d74-23affee5d9d5'  # Intune Administrator
    '44367163-eba1-44c3-98af-f5787879f96a'  # Dynamics 365 Administrator
    'b0f54661-2d74-4c50-afa3-1ec803f12efe'  # Billing Administrator
    '729827e3-9c14-49f7-bb1b-9608f156bbb8'  # Helpdesk Administrator
)

$legacyClientTypes = @('exchangeActiveSync', 'other')

# ─────────────────────────────────────────────
# 4. Helper functions
# ─────────────────────────────────────────────
$script:groupCache = @{}
$script:userCache = @{}

function Test-GroupExists {
    param([string]$GroupId)
    if ($script:groupCache.ContainsKey($GroupId)) { return $script:groupCache[$GroupId] }
    try {
        $g = Get-MgGroup -GroupId $GroupId -Property Id, DisplayName -ErrorAction Stop
        $script:groupCache[$GroupId] = $g
        return $g
    }
    catch {
        $script:groupCache[$GroupId] = $null
        return $null
    }
}

function Get-GroupMemberCount {
    param([string]$GroupId)
    try {
        $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
        return @($members).Count
    }
    catch { return -1 }
}

function Test-UserExists {
    param([string]$UserId)
    if ($script:userCache.ContainsKey($UserId)) { return $script:userCache[$UserId] }
    try {
        $u = Get-MgUser -UserId $UserId -Property Id, DisplayName -ErrorAction Stop
        $script:userCache[$UserId] = $u
        return $u
    }
    catch {
        $script:userCache[$UserId] = $null
        return $null
    }
}

function Get-PolicyCategory {
    param($Policy)
    $categories = [System.Collections.Generic.List[string]]::new()

    switch ($Policy.State) {
        'enabled'                           { $categories.Add('Enforced') }
        'enabledForReportingButNotEnforced' { $categories.Add('Report-Only') }
        'disabled'                          { $categories.Add('Disabled') }
    }

    $cond = $Policy.Conditions
    if ($cond.Users.IncludeRoles -and ($cond.Users.IncludeRoles | Where-Object { $_ -in $adminRoleIds })) {
        $categories.Add('Admins')
    }
    if ($cond.Users.IncludeGuestsOrExternalUsers -or ($cond.Users.IncludeUsers -contains 'GuestsOrExternalUsers')) {
        $categories.Add('Guests')
    }
    if ($cond.Users.IncludeUsers -contains 'All') { $categories.Add('All Users') }

    $gc = $Policy.GrantControls
    if ($gc) {
        $bi = $gc.BuiltInControls
        if ($bi -contains 'block') { $categories.Add('Block') }
        if ($bi -contains 'mfa') { $categories.Add('MFA') }
        if ($bi -contains 'compliantDevice') { $categories.Add('Device Compliance') }
        if ($bi -contains 'domainJoinedDevice') { $categories.Add('Hybrid Join') }
        if ($bi -contains 'approvedApplication') { $categories.Add('Approved App') }
        if ($gc.AuthenticationStrength) { $categories.Add('Auth Strength') }
    }

    $sc = $Policy.SessionControls
    if ($sc -and ($sc.SignInFrequency -or $sc.PersistentBrowser)) { $categories.Add('Session Control') }

    if ($cond.UserRiskLevels -or $cond.SignInRiskLevels) { $categories.Add('Risk-Based') }
    if ($cond.Locations) { $categories.Add('Location-Based') }
    if ($cond.Platforms) { $categories.Add('Platform-Based') }
    if ($cond.ClientAppTypes -and ($cond.ClientAppTypes | Where-Object { $_ -in $legacyClientTypes })) {
        $categories.Add('Legacy Auth')
    }
    if ($cond.Devices) { $categories.Add('Device-Based') }

    return ($categories | Select-Object -Unique) -join ', '
}

# ─────────────────────────────────────────────
# 5. Run audit checks
# ─────────────────────────────────────────────
$now = [DateTime]::UtcNow
$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param([string]$Severity, [string]$Category, [string]$Check,
          [string]$PolicyName, [string]$PolicyId, [string]$Detail)
    $findings.Add([PSCustomObject]@{
        Severity   = $Severity;   Category  = $Category;  Check      = $Check
        PolicyName = $PolicyName; PolicyId  = $PolicyId;  Detail     = $Detail
    })
}

Write-Host "Running security gap checks ..." -ForegroundColor Cyan
$enabledPolicies = $policies | Where-Object { $_.State -eq 'enabled' }

# ── 1. MFA baseline for all users ──
$mfaBaseline = $enabledPolicies | Where-Object {
    $_.Conditions.Users.IncludeUsers -contains 'All' -and
    $_.Conditions.Applications.IncludeApplications -contains 'All' -and
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength)
}
if (-not $mfaBaseline) {
    Add-Finding -Severity 'Critical' -Category 'Security Gap' `
        -Check 'Missing MFA Baseline' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy requires MFA for all users on all cloud apps.'
}

# ── 2. Admin MFA ──
$adminMfa = $enabledPolicies | Where-Object {
    $_.Conditions.Users.IncludeRoles -and
    ($_.Conditions.Users.IncludeRoles | Where-Object { $_ -in $adminRoleIds }) -and
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength)
}
if (-not $adminMfa -and -not $mfaBaseline) {
    Add-Finding -Severity 'Critical' -Category 'Security Gap' `
        -Check 'Admin MFA Gap' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy requires MFA for privileged admin roles, and no all-user MFA baseline exists.'
}

# ── 3. Legacy auth blocked ──
$legacyBlock = $enabledPolicies | Where-Object {
    $_.Conditions.ClientAppTypes -and
    ($_.Conditions.ClientAppTypes | Where-Object { $_ -in $legacyClientTypes }) -and
    $_.GrantControls -and $_.GrantControls.BuiltInControls -contains 'block'
}
if (-not $legacyBlock) {
    Add-Finding -Severity 'Critical' -Category 'Security Gap' `
        -Check 'Legacy Auth Not Blocked' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy blocks legacy authentication (IMAP, POP, SMTP AUTH, Exchange ActiveSync). These bypass MFA.'
}

# ── 4. Phishing-resistant auth for admins ──
$adminPhishResistant = $enabledPolicies | Where-Object {
    $_.Conditions.Users.IncludeRoles -and
    ($_.Conditions.Users.IncludeRoles | Where-Object { $_ -in $adminRoleIds }) -and
    $_.GrantControls -and $_.GrantControls.AuthenticationStrength
}
if ($adminMfa -and -not $adminPhishResistant) {
    Add-Finding -Severity 'Critical' -Category 'Security Gap' `
        -Check 'No Phishing-Resistant Auth for Admins' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'Admin policies use generic MFA instead of phishing-resistant authentication strength (FIDO2, WHfB, certificate-based).'
}

# ── 5. Guest MFA ──
$guestMfa = $enabledPolicies | Where-Object {
    ($_.Conditions.Users.IncludeGuestsOrExternalUsers -or
     $_.Conditions.Users.IncludeUsers -contains 'GuestsOrExternalUsers' -or
     $_.Conditions.Users.IncludeUsers -contains 'All') -and
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength)
}
$guestExcluded = $enabledPolicies | Where-Object {
    $_.Conditions.Users.IncludeUsers -contains 'All' -and
    ($_.Conditions.Users.ExcludeGuestsOrExternalUsers -or
     $_.Conditions.Users.ExcludeUsers -contains 'GuestsOrExternalUsers')
}
if (-not $guestMfa -and $guestExcluded) {
    Add-Finding -Severity 'High' -Category 'Security Gap' `
        -Check 'Guest MFA Gap' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'Guest/external users are excluded from MFA policies but no separate guest MFA policy exists.'
}

# ── 6. User risk policy ──
$userRiskPolicy = $enabledPolicies | Where-Object {
    $_.Conditions.UserRiskLevels -and @($_.Conditions.UserRiskLevels).Count -gt 0 -and
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or
     $_.GrantControls.BuiltInControls -contains 'passwordChange' -or
     $_.GrantControls.BuiltInControls -contains 'block')
}
if (-not $userRiskPolicy) {
    Add-Finding -Severity 'High' -Category 'Security Gap' `
        -Check 'No User Risk Policy' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy responds to elevated user risk (compromised credentials). Requires Entra ID P2.'
}

# ── 7. Sign-in risk policy ──
$signInRiskPolicy = $enabledPolicies | Where-Object {
    $_.Conditions.SignInRiskLevels -and @($_.Conditions.SignInRiskLevels).Count -gt 0 -and
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.BuiltInControls -contains 'block')
}
if (-not $signInRiskPolicy) {
    Add-Finding -Severity 'High' -Category 'Security Gap' `
        -Check 'No Sign-In Risk Policy' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy responds to elevated sign-in risk (suspicious sign-ins, impossible travel). Requires Entra ID P2.'
}

# ── 8. Device compliance ──
$deviceCompliance = $enabledPolicies | Where-Object {
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'compliantDevice' -or
     $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice')
}
if (-not $deviceCompliance) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'No Device Compliance' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy requires compliant or hybrid-joined devices.'
}

# ── 9. Location controls ──
$locationPolicies = $enabledPolicies | Where-Object { $_.Conditions.Locations }
if (-not $locationPolicies) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'No Location Controls' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy uses location-based conditions.'
}
if ($namedLocations.Count -eq 0) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'No Named Locations' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No named/trusted locations are defined in the tenant.'
}

# ── 10. Session controls ──
$sessionPolicies = $enabledPolicies | Where-Object {
    $_.SessionControls -and ($_.SessionControls.SignInFrequency -or $_.SessionControls.PersistentBrowser)
}
if (-not $sessionPolicies) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'No Session Controls' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy sets sign-in frequency or persistent browser controls.'
}

# ── 11. Break-glass account governance ──
Write-Host "Checking break-glass account governance ..." -ForegroundColor Cyan
$breakGlassAccounts = @()
$allUsers = $null
try {
    $allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName -ErrorAction Stop
    $breakGlassAccounts = @($allUsers | Where-Object {
        $_.DisplayName -match '(?i)(break.?glass|emergency.?access|BreakGlass)' -or
        $_.UserPrincipalName -match '(?i)(break.?glass|emergency.?access)'
    })
}
catch { Write-Warning "Could not enumerate users for break-glass check: $_" }

if ($breakGlassAccounts.Count -gt 0) {
    $bgIds = $breakGlassAccounts | ForEach-Object { $_.Id }
    $blockPolicies = $enabledPolicies | Where-Object {
        $_.GrantControls -and $_.GrantControls.BuiltInControls -contains 'block'
    }
    foreach ($bp in $blockPolicies) {
        $exUsers = $bp.Conditions.Users.ExcludeUsers
        $exGroups = $bp.Conditions.Users.ExcludeGroups
        $bgExcluded = $false
        foreach ($bgId in $bgIds) {
            if ($exUsers -contains $bgId) { $bgExcluded = $true; break }
        }
        if (-not $bgExcluded -and $exGroups) {
            foreach ($gid in $exGroups) {
                try {
                    $members = Get-MgGroupMember -GroupId $gid -All -ErrorAction Stop
                    $memberIds = $members | ForEach-Object { $_.Id }
                    foreach ($bgId in $bgIds) {
                        if ($memberIds -contains $bgId) { $bgExcluded = $true; break }
                    }
                }
                catch { }
                if ($bgExcluded) { break }
            }
        }
        if (-not $bgExcluded) {
            Add-Finding -Severity 'High' -Category 'Security Gap' `
                -Check 'Break-Glass Not Excluded from Block' `
                -PolicyName $bp.DisplayName -PolicyId $bp.Id `
                -Detail "Break-glass account(s) ($($breakGlassAccounts.DisplayName -join ', ')) not excluded from this block policy."
        }
    }
}
elseif ($null -ne $allUsers) {
    Add-Finding -Severity 'High' -Category 'Governance' `
        -Check 'No Break-Glass Accounts Detected' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No emergency access / break-glass accounts detected. Microsoft recommends at least 2.'
}

# ── 12. High-value apps not specifically protected ──
$highValueApps = @{
    '00000002-0000-0ff1-ce00-000000000000' = 'Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'SharePoint Online'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure Portal'
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Management'
}
foreach ($appId in $highValueApps.Keys) {
    $appName = $highValueApps[$appId]
    $appSpecific = $enabledPolicies | Where-Object {
        $_.Conditions.Applications.IncludeApplications -contains $appId
    }
    if (-not $appSpecific) {
        $coveredByAll = $enabledPolicies | Where-Object {
            $_.Conditions.Applications.IncludeApplications -contains 'All' -and
            -not ($_.Conditions.Applications.ExcludeApplications -contains $appId)
        }
        if ($coveredByAll) {
            Add-Finding -Severity 'Info' -Category 'Governance' `
                -Check "No App-Specific Policy: $appName" -PolicyName 'N/A' -PolicyId 'N/A' `
                -Detail "$appName is only covered by broad 'All cloud apps' policies. Consider app-specific hardening."
        }
        else {
            Add-Finding -Severity 'High' -Category 'Security Gap' `
                -Check "High-Value App Not Protected: $appName" -PolicyName 'N/A' -PolicyId 'N/A' `
                -Detail "$appName has no CA policy coverage."
        }
    }
}

# ── 13. Mobile app protection gap ──
$mobilePlatforms = @('iOS', 'android')
$mobileProtection = $enabledPolicies | Where-Object {
    $_.Conditions.Platforms -and
    ($_.Conditions.Platforms.IncludePlatforms | Where-Object { $_ -in $mobilePlatforms -or $_ -eq 'all' }) -and
    $_.GrantControls -and
    ($_.GrantControls.BuiltInControls -contains 'approvedApplication' -or
     $_.GrantControls.BuiltInControls -contains 'compliantApplication')
}
if (-not $mobileProtection) {
    Add-Finding -Severity 'High' -Category 'Security Gap' `
        -Check 'Mobile App Protection Gap' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy requires approved or MAM-protected apps for iOS/Android.'
}

# ── 14. Security info registration not protected ──
$registrationPolicy = $enabledPolicies | Where-Object {
    $condObj = $_.Conditions
    $ua = $null
    try { $ua = $condObj.UserActions } catch { }
    $ua -and $ua.IncludeUserActions -and
    ($ua.IncludeUserActions -contains 'urn:user:registerdevice' -or
     $ua.IncludeUserActions -contains 'urn:user:registersecurityinfo')
}
if (-not $registrationPolicy) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'Security Info Registration Not Protected' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No CA policy gates MFA/security info registration. Attackers with stolen passwords can register their own MFA methods.'
}

# ── 15. Terms of Use not enforced ──
$touPolicies = $enabledPolicies | Where-Object {
    $tou = $null
    try { $tou = $_.GrantControls.TermsOfUse } catch { }
    $_.GrantControls -and $tou -and @($tou).Count -gt 0
}
if (-not $touPolicies) {
    try {
        $agreements = Get-MgAgreement -ErrorAction Stop
        if (@($agreements).Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Governance' `
                -Check 'Terms of Use Defined But Not Enforced' -PolicyName 'N/A' -PolicyId 'N/A' `
                -Detail "Found $(@($agreements).Count) TOU agreement(s) but no CA policy enforces acceptance."
        }
    }
    catch { }
}

# ── 16. Unknown/unsupported platforms ──
$platformBlock = $enabledPolicies | Where-Object {
    $_.Conditions.Platforms -and
    $_.GrantControls -and $_.GrantControls.BuiltInControls -contains 'block' -and
    ($_.Conditions.Platforms.IncludePlatforms -contains 'all' -or
     $_.Conditions.Platforms.IncludePlatforms -contains 'unknownFutureValue')
}
if (-not $platformBlock) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'Unknown Platforms Not Blocked' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No enforced policy blocks unknown/unsupported device platforms.'
}

# ── 17. Token protection / resilience controls ──
$resilienceOverride = $enabledPolicies | Where-Object {
    $drd = $null
    try { $drd = $_.SessionControls.DisableResilienceDefaults } catch { }
    $_.SessionControls -and $drd -eq $true
}
if (-not $resilienceOverride) {
    Add-Finding -Severity 'Info' -Category 'Governance' `
        -Check 'Resilience Defaults Not Overridden' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No policy overrides resilience defaults. During outages, cached tokens may grant access to sensitive apps.'
}

# ── 18. Workload identity gap ──
$workloadPolicies = $enabledPolicies | Where-Object {
    $ca = $null; $isp = $null
    try { $ca = $_.Conditions.ClientApplications } catch { }
    try { $isp = $_.Conditions.Applications.IncludeServicePrincipals } catch { }
    $ca -or ($isp -and @($isp).Count -gt 0)
}
if (-not $workloadPolicies) {
    Add-Finding -Severity 'Medium' -Category 'Security Gap' `
        -Check 'Workload Identity Gap' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No CA policy targets workload identities (service principals). Requires Entra Workload Identities Premium.'
}

# ── 19. Authentication context ──
$authContexts = @()
try { $authContexts = @(Get-MgIdentityConditionalAccessAuthenticationContextClassReference -ErrorAction Stop) }
catch { }
if ($authContexts.Count -eq 0) {
    Add-Finding -Severity 'Info' -Category 'Governance' `
        -Check 'No Authentication Contexts Defined' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail 'No authentication contexts defined. They enable step-up auth for sensitive actions.'
}
else {
    $authCtxPolicies = $enabledPolicies | Where-Object {
        $acr = $null
        try { $acr = $_.Conditions.AuthenticationContextClassReferences } catch { }
        $acr -and @($acr).Count -gt 0
    }
    if (-not $authCtxPolicies) {
        Add-Finding -Severity 'Medium' -Category 'Governance' `
            -Check 'Authentication Contexts Not Used in CA' -PolicyName 'N/A' -PolicyId 'N/A' `
            -Detail "Found $($authContexts.Count) auth context(s) but no CA policy references them."
    }
}

# ── Per-policy checks ──
Write-Host "Running per-policy checks ..." -ForegroundColor Cyan

foreach ($policy in $policies) {
    $pName    = $policy.DisplayName
    $polId    = $policy.Id

    # 20. Report-only too long
    if ($policy.State -eq 'enabledForReportingButNotEnforced' -and $policy.ModifiedDateTime) {
        $daysSinceModified = ($now - $policy.ModifiedDateTime.ToUniversalTime()).TotalDays
        if ($daysSinceModified -ge $ReportOnlyThresholdDays) {
            Add-Finding -Severity 'Warning' -Category 'Hygiene' `
                -Check 'Report-Only Too Long' -PolicyName $pName -PolicyId $polId `
                -Detail "In report-only mode for $([Math]::Floor($daysSinceModified)) days (threshold: $ReportOnlyThresholdDays)."
        }
    }

    # 21. Disabled too long
    if ($policy.State -eq 'disabled' -and $policy.ModifiedDateTime) {
        $daysSinceModified = ($now - $policy.ModifiedDateTime.ToUniversalTime()).TotalDays
        if ($daysSinceModified -ge $DisabledThresholdDays) {
            Add-Finding -Severity 'Warning' -Category 'Hygiene' `
                -Check 'Disabled Policy' -PolicyName $pName -PolicyId $polId `
                -Detail "Disabled for $([Math]::Floor($daysSinceModified)) days (threshold: $DisabledThresholdDays)."
        }
    }

    $cond = $policy.Conditions

    # 22. Orphaned included users
    if ($cond.Users.IncludeUsers) {
        foreach ($uid in $cond.Users.IncludeUsers) {
            if ($uid -in @('All', 'GuestsOrExternalUsers', 'None')) { continue }
            if (-not (Test-UserExists -UserId $uid)) {
                Add-Finding -Severity 'Warning' -Category 'Hygiene' `
                    -Check 'Orphaned User Reference' -PolicyName $pName -PolicyId $polId `
                    -Detail "Included user ID '$uid' no longer exists."
            }
        }
    }

    # 23. Orphaned excluded users
    if ($cond.Users.ExcludeUsers) {
        foreach ($uid in $cond.Users.ExcludeUsers) {
            if ($uid -in @('GuestsOrExternalUsers')) { continue }
            if (-not (Test-UserExists -UserId $uid)) {
                Add-Finding -Severity 'High' -Category 'Security Gap' `
                    -Check 'Orphaned Exclusion (User)' -PolicyName $pName -PolicyId $polId `
                    -Detail "Excluded user ID '$uid' no longer exists. Stale exclusion."
            }
        }
    }

    # 24/25. Orphaned/empty included groups + orphaned/large excluded groups
    if ($cond.Users.IncludeGroups) {
        foreach ($gid in $cond.Users.IncludeGroups) {
            $grp = Test-GroupExists -GroupId $gid
            if (-not $grp) {
                Add-Finding -Severity 'Warning' -Category 'Hygiene' `
                    -Check 'Orphaned Group Reference' -PolicyName $pName -PolicyId $polId `
                    -Detail "Included group ID '$gid' no longer exists."
            }
            else {
                $mc = Get-GroupMemberCount -GroupId $gid
                if ($mc -eq 0) {
                    Add-Finding -Severity 'Warning' -Category 'Hygiene' `
                        -Check 'Empty Target Group' -PolicyName $pName -PolicyId $polId `
                        -Detail "Included group '$($grp.DisplayName)' has 0 members."
                }
            }
        }
    }

    if ($cond.Users.ExcludeGroups) {
        foreach ($gid in $cond.Users.ExcludeGroups) {
            $grp = Test-GroupExists -GroupId $gid
            if (-not $grp) {
                Add-Finding -Severity 'High' -Category 'Security Gap' `
                    -Check 'Orphaned Exclusion (Group)' -PolicyName $pName -PolicyId $polId `
                    -Detail "Excluded group ID '$gid' no longer exists."
            }
            else {
                $mc = Get-GroupMemberCount -GroupId $gid
                if ($mc -gt $LargeGroupThreshold) {
                    Add-Finding -Severity 'High' -Category 'Security Gap' `
                        -Check 'Overly Broad Exclusion' -PolicyName $pName -PolicyId $polId `
                        -Detail "Excluded group '$($grp.DisplayName)' has $mc members (threshold: $LargeGroupThreshold)."
                }
            }
        }
    }
}

# ── 26. Duplicate / overlapping policies ──
Write-Host "Checking for duplicate policies ..." -ForegroundColor Cyan
$policySignatures = @{}
foreach ($policy in $enabledPolicies) {
    $sig = "$($policy.Conditions.Users.IncludeUsers -join ',')|" +
           "$($policy.Conditions.Users.IncludeGroups -join ',')|" +
           "$($policy.Conditions.Users.IncludeRoles -join ',')|" +
           "$($policy.Conditions.Applications.IncludeApplications -join ',')|" +
           "$($policy.Conditions.ClientAppTypes -join ',')|" +
           "$($policy.GrantControls.BuiltInControls -join ',')"
    if ($policySignatures.ContainsKey($sig)) {
        Add-Finding -Severity 'Info' -Category 'Hygiene' `
            -Check 'Potential Duplicate' -PolicyName $policy.DisplayName -PolicyId $policy.Id `
            -Detail "Same scope and controls as '$($policySignatures[$sig])'."
    }
    else { $policySignatures[$sig] = $policy.DisplayName }
}

# ── 27. Sign-in activity (policies never triggered) ──
Write-Host "Checking sign-in logs for policy activity (last $SignInLookbackDays days) ..." -ForegroundColor Cyan
$lookbackDate = $now.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$triggeredPolicyIds = [System.Collections.Generic.HashSet[string]]::new()

try {
    $signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $lookbackDate" `
        -Top 1000 -Property AppliedConditionalAccessPolicies -ErrorAction Stop
    foreach ($signIn in $signIns) {
        if ($signIn.AppliedConditionalAccessPolicies) {
            foreach ($applied in $signIn.AppliedConditionalAccessPolicies) {
                if ($applied.Id) { $triggeredPolicyIds.Add($applied.Id) | Out-Null }
            }
        }
    }
    foreach ($policy in $enabledPolicies) {
        if (-not $triggeredPolicyIds.Contains($policy.Id)) {
            Add-Finding -Severity 'Warning' -Category 'Hygiene' `
                -Check 'Never Triggered' -PolicyName $policy.DisplayName -PolicyId $policy.Id `
                -Detail "No sign-in matches found in the last $SignInLookbackDays days."
        }
    }
}
catch {
    Write-Warning "Could not query sign-in logs: $_"
    Add-Finding -Severity 'Info' -Category 'Hygiene' `
        -Check 'Sign-In Check Skipped' -PolicyName 'N/A' -PolicyId 'N/A' `
        -Detail "Could not query sign-in logs. Ensure AuditLog.Read.All permission and Entra ID P1/P2."
}

# ─────────────────────────────────────────────
# 6. Build summary
# ─────────────────────────────────────────────
$totalPolicies   = $policies.Count
$enforcedCount   = @($policies | Where-Object State -eq 'enabled').Count
$reportOnlyCount = @($policies | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
$disabledCount   = @($policies | Where-Object State -eq 'disabled').Count

$criticalCount = @($findings | Where-Object Severity -eq 'Critical').Count
$highCount     = @($findings | Where-Object Severity -eq 'High').Count
$mediumCount   = @($findings | Where-Object Severity -eq 'Medium').Count
$warningCount  = @($findings | Where-Object Severity -eq 'Warning').Count
$infoCount     = @($findings | Where-Object Severity -eq 'Info').Count

Write-Host "Audit complete: $($findings.Count) finding(s)." -ForegroundColor Yellow

# ─────────────────────────────────────────────
# 7. Build HTML report
# ─────────────────────────────────────────────
Write-Host "Generating HTML report ..." -ForegroundColor Cyan

$severityColors   = @{ 'Critical'='#e74c3c'; 'High'='#e67e22'; 'Medium'='#f39c12'; 'Warning'='#3498db'; 'Info'='#95a5a6' }
$severityBgColors = @{ 'Critical'='#fde8e8'; 'High'='#fef3e8'; 'Medium'='#fef9e8'; 'Warning'='#e8f4fd'; 'Info'='#f5f5f5' }

$findingRows = ($findings | Sort-Object @{Expression={
    switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Warning'{3} 'Info'{4} }
}}, Check | ForEach-Object {
    $color = $severityColors[$_.Severity]
    $bg    = $severityBgColors[$_.Severity]
    "<tr style=`"background-color:$bg;`">" +
    "<td><strong style=`"color:$color;`">$($_.Severity)</strong></td>" +
    "<td>$($_.Category)</td><td>$($_.Check)</td>" +
    "<td>$($_.PolicyName)</td><td>$($_.Detail)</td></tr>"
}) -join "`n"

$inventoryRows = ($policies | Sort-Object State, DisplayName | ForEach-Object {
    $stateColor = switch ($_.State) { 'enabled'{'#27ae60'} 'enabledForReportingButNotEnforced'{'#f39c12'} 'disabled'{'#e74c3c'} }
    $stateLabel = switch ($_.State) { 'enabled'{'Enforced'} 'enabledForReportingButNotEnforced'{'Report-Only'} 'disabled'{'Disabled'} }
    $cats = Get-PolicyCategory -Policy $_
    "<tr><td>$($_.DisplayName)</td>" +
    "<td><strong style=`"color:$stateColor;`">$stateLabel</strong></td>" +
    "<td>$cats</td><td style=`"font-size:12px;`">$($_.Id)</td></tr>"
}) -join "`n"

$htmlBody = "<!DOCTYPE html>" +
"<html><head><style>" +
"body { font-family: Segoe UI, Arial, sans-serif; color: #333; margin: 20px; } " +
"h1 { color: #2c3e50; } " +
"h2 { color: #34495e; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; margin-top: 30px; } " +
"table { border-collapse: collapse; width: 100%; margin-top: 12px; } " +
"th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 14px; } " +
"th { background-color: #2c3e50; color: #fff; } " +
".summary-box { display: inline-block; padding: 15px 25px; margin: 5px; border-radius: 8px; text-align: center; } " +
".stat-number { font-size: 28px; font-weight: bold; display: block; } " +
".stat-label { font-size: 13px; color: #666; } " +
".note { font-size: 13px; color: #888; margin-top: 20px; } " +
"</style></head><body>" +
"<h1>&#128737; Conditional Access Policy Audit Report</h1>" +
"<p>Tenant: <strong>$TenantId</strong> | Generated: <strong>$($now.ToString('yyyy-MM-dd HH:mm:ss')) UTC</strong></p>" +
"<h2>Policy Summary</h2><div>" +
"<div class=`"summary-box`" style=`"background:#e8f8f5;`"><span class=`"stat-number`">$totalPolicies</span><span class=`"stat-label`">Total</span></div>" +
"<div class=`"summary-box`" style=`"background:#eafaf1;`"><span class=`"stat-number`" style=`"color:#27ae60;`">$enforcedCount</span><span class=`"stat-label`">Enforced</span></div>" +
"<div class=`"summary-box`" style=`"background:#fef9e7;`"><span class=`"stat-number`" style=`"color:#f39c12;`">$reportOnlyCount</span><span class=`"stat-label`">Report-Only</span></div>" +
"<div class=`"summary-box`" style=`"background:#fdedec;`"><span class=`"stat-number`" style=`"color:#e74c3c;`">$disabledCount</span><span class=`"stat-label`">Disabled</span></div></div>" +
"<h2>Audit Findings ($($findings.Count) total)</h2><div>" +
"<div class=`"summary-box`" style=`"background:#fde8e8;`"><span class=`"stat-number`" style=`"color:#e74c3c;`">$criticalCount</span><span class=`"stat-label`">Critical</span></div>" +
"<div class=`"summary-box`" style=`"background:#fef3e8;`"><span class=`"stat-number`" style=`"color:#e67e22;`">$highCount</span><span class=`"stat-label`">High</span></div>" +
"<div class=`"summary-box`" style=`"background:#fef9e8;`"><span class=`"stat-number`" style=`"color:#f39c12;`">$mediumCount</span><span class=`"stat-label`">Medium</span></div>" +
"<div class=`"summary-box`" style=`"background:#e8f4fd;`"><span class=`"stat-number`" style=`"color:#3498db;`">$warningCount</span><span class=`"stat-label`">Warning</span></div>" +
"<div class=`"summary-box`" style=`"background:#f5f5f5;`"><span class=`"stat-number`" style=`"color:#95a5a6;`">$infoCount</span><span class=`"stat-label`">Info</span></div></div>" +
"<table><tr><th>Severity</th><th>Category</th><th>Check</th><th>Policy</th><th>Detail</th></tr>" +
$findingRows + "</table>" +
"<h2>Policy Inventory</h2>" +
"<table><tr><th>Policy Name</th><th>Status</th><th>Categories</th><th>Policy ID</th></tr>" +
$inventoryRows + "</table>" +
"<p class=`"note`">Generated by Audit-ConditionalAccessPolicies.ps1. " +
"Sign-in lookback: $SignInLookbackDays days. Report-only threshold: $ReportOnlyThresholdDays days. " +
"Disabled threshold: $DisabledThresholdDays days. Large group: $LargeGroupThreshold members.</p>" +
"</body></html>"

# ─────────────────────────────────────────────
# 8. Output report
# ─────────────────────────────────────────────
if ($OutputPath) {
    $htmlBody | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "Report saved to $OutputPath" -ForegroundColor Green
}

if ($MailFrom -and $MailTo) {
    $subject = "CA Policy Audit - $criticalCount critical, $highCount high, $mediumCount medium findings"
    $toRecipients = @($MailTo | ForEach-Object { @{ EmailAddress = @{ Address = $_ } } })
    $mailBody = @{
        Message = @{
            Subject      = $subject
            Body         = @{ ContentType = 'HTML'; Content = $htmlBody }
            ToRecipients = $toRecipients
        }
    }
    Send-MgUserMail -UserId $MailFrom -BodyParameter $mailBody -ErrorAction Stop
    Write-Host "Audit report emailed from $MailFrom to $($MailTo -join ', ')." -ForegroundColor Green
}

if (-not $OutputPath -and -not ($MailFrom -and $MailTo)) {
    Write-Host "No -OutputPath or -MailFrom/-MailTo specified. Displaying summary only." -ForegroundColor Yellow
}

# ─────────────────────────────────────────────
# 9. Console summary
# ─────────────────────────────────────────────
Write-Host "`n=== AUDIT SUMMARY ===" -ForegroundColor Yellow
Write-Host "Policies: $totalPolicies ($enforcedCount enforced, $reportOnlyCount report-only, $disabledCount disabled)"
Write-Host "Findings: $criticalCount critical, $highCount high, $mediumCount medium, $warningCount warning, $infoCount info"

if ($findings.Count -gt 0) {
    Write-Host "`nTop findings:" -ForegroundColor Cyan
    $findings | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Warning'{3} 'Info'{4} }
    }} | Select-Object -First 10 |
        Format-Table Severity, Check, PolicyName, Detail -AutoSize -Wrap
}

Disconnect-MgGraph | Out-Null
Write-Host "Done." -ForegroundColor Green
