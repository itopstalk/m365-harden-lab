#Requires -Version 7.2

<#
.SYNOPSIS
Configures the Microsoft 365 lab controls in one standalone script.

.DESCRIPTION
Combines scripts 04, 06, 10, 12, 14, 16, 18, 20, 30, 40, 42, and 44.
The necessary SecureM365.Common.psm1 helpers are embedded. No other repository
script or module is loaded. Requires Windows, PowerShell 7.2 or later, and the
Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns,
Microsoft.Graph.Identity.Governance, and MicrosoftTeams modules.

Creates or verifies the named cloud-only emergency accounts, including permanent
Global Administrator assignments. Newly generated passwords are saved and
recovery-verified in a Windows user-scoped DPAPI artifact before any user is
created. Existing passwords are never read or reset.

Creates or verifies the dedicated Teams application and its local non-exportable
RSA certificate. The application receives only Microsoft Graph Organization.Read.All
and Teams Communications Administrator, as in script 06. The resulting certificate
connection is used for all three Global meeting-policy settings.

Creates missing CA001-CA005 policies initially in report-only mode. Unless
-ReportOnly is selected, enables them using script 20's reviewed-policy approach
after explicit emergency-access and MFA-readiness confirmation. Existing matching
enabled policies are left enabled. Existing report-only policies can be promoted;
disabled, ambiguous, or differently configured policies require manual review.
Graph OData response annotations are ignored when comparing policy settings.
Genuine mismatches include the expected and actual normalized JSON for review.
Unrelated policies and custom Teams meeting policies are never changed.

Removes ordinary-user application-consent assignments, preserving other grant
policies. Sets the Global Teams policy to InvitedUsers lobby bypass,
OrganizerOnlyUserOverride presenters, and disabled anonymous meeting join.
Consent and Teams settings are configured before activating sign-in restrictions.

Security Defaults must already be disabled; this script never changes it.
Appropriate licenses and active administrative roles remain prerequisites, as in
the original scripts. In particular, risk-based policies require Entra ID P2.
This script does not assign roles to the signed-in operator or configure SSPR,
authentication-method enrollment, monitoring, or password writeback.

CA005 deliberately retains script 18's passwordChange + MFA authentication-strength
grant. Current Microsoft Graph documentation instead describes mfa + passwordChange
or authenticationStrength + riskRemediation. This compatibility caveat is retained
at the operator's request: no grant is silently substituted or migrated. A Graph
rejection stops configuration and is reported, not treated as a successful control.
Successful configuration readback is not a test of the live user-remediation flow.

.PARAMETER TenantId
Worldwide-cloud Microsoft Entra tenant GUID. Prompts when omitted.

.PARAMETER AccountName
Two to ten distinct emergency-account username prefixes in the tenant's initial,
verified, managed onmicrosoft.com domain. Defaults to emergency-access-01 and
emergency-access-02. Existing accounts must match the cloud-only account settings
and have a direct, permanent, tenant-wide Global Administrator assignment.

.PARAMETER PasswordFilePath
DPAPI artifact for newly created accounts only. Defaults to
Documents\SecureM365\EmergencyAccessPasswords-<tenant>.json. Reusing accounts does
not generate a new password file. Choose a different path when adding accounts
if an earlier credential artifact must be retained.

.PARAMETER OverwritePasswordFile
Explicitly allow replacement of an existing password artifact. Back it up first.

.PARAMETER TeamsApplicationDisplayName
Dedicated single-tenant application's display name, as in script 06.

.PARAMETER TeamsCertificateSubject
Certificate subject in Cert:\CurrentUser\My, as in script 06.

.PARAMETER CertificateValidityMonths
Validity of a newly generated certificate, from 1 to 24 months. Defaults to 12.
Existing certificates are validated, not renewed or replaced.

.PARAMETER TemporaryExceptionAccountId
Explicit temporary user exclusions for the legacy-authentication block. Defaults
to none, as in script 14. The emergency accounts are automatically excluded from
CA001, CA002, CA004, and CA005, but not automatically excluded from CA003.

.PARAMETER ReportOnly
Leave new and existing matching report-only CA policies staged. Does not disable
already-enabled policies. Other requested configuration is still applied.
Rerun this same script without this switch after reviewing policy impact.

.PARAMETER EmergencyAccessReady
Explicitly attest that the reused emergency accounts have tested access,
phishing-resistant MFA, and permanent Global Administrator assignments, and
that affected users are ready for MFA, modern authentication, and risk remediation.
Permitted only when all requested emergency accounts already exist.
Otherwise enforcement requires an interactive confirmation after provisioning.
-Confirm:$false does not bypass that readiness confirmation.
The interactive readiness prompt defaults to No.

.PARAMETER UseGraphDeviceCode
Use Graph device-code authentication. Alias: UseDeviceCode.

.PARAMETER UseGraphBrowserPkce
Use the embedded browser-PKCE flow for managed terminals.

.PARAMETER PropagationRetryCount
Maximum readback/connection attempts. Defaults to 6.
Policy-not-found HTTP 404 responses are retried to allow newly created policies
to propagate. Exhaustion stops the run without recreating the policy.

.PARAMETER PropagationRetryDelaySeconds
Seconds between propagation attempts. Defaults to 10.

.PARAMETER PassThru
Return the structured plan or final configuration report, in addition to host
messages. Passwords and private keys are never included in these results.

.NOTES
-WhatIf performs authenticated discovery with read scopes, but does not create
passwords, files, certificates, users, applications, grants, or policies.
It does not attempt a Teams connection with an application that is not yet created.
One high-impact ShouldProcess confirmation covers the displayed configuration plan.
Existing identities and policies are never silently repaired or overwritten.
Any failure stops subsequent work and reports confirmed changes; no automatic
rollback or success-shaped fallback is performed.

.EXAMPLE
.\ZZ-ConfigureM365Status.ps1 -UseGraphBrowserPkce -WhatIf

.EXAMPLE
.\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId -UseGraphBrowserPkce

.EXAMPLE
$result = .\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId -ReportOnly -PassThru

.EXAMPLE
.\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId -EmergencyAccessReady -Confirm:$false

.LINK
https://learn.microsoft.com/graph/api/resources/conditionalaccessgrantcontrols
.LINK
https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignmentscheduleinstances
.LINK
https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [string] $TenantId,

    [ValidateCount(2, 10)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')]
    [string[]] $AccountName = @("emergency-access-01", "emergency-access-02"),

    [string] $PasswordFilePath,
    [switch] $OverwritePasswordFile,

    [ValidateNotNullOrEmpty()]
    [string] $TeamsApplicationDisplayName = "SecureM365 Teams Meeting Policy Automation",

    [ValidatePattern('^CN=[^,=]+$')]
    [string] $TeamsCertificateSubject = "CN=SecureM365 Teams Meeting Policy Automation",

    [ValidateRange(1, 24)]
    [int] $CertificateValidityMonths = 12,

    [guid[]] $TemporaryExceptionAccountId = @(),
    [switch] $ReportOnly,
    [switch] $EmergencyAccessReady,
    [Alias("UseDeviceCode")]
    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce,

    [ValidateRange(1, 12)]
    [int] $PropagationRetryCount = 6,

    [ValidateRange(0, 60)]
    [int] $PropagationRetryDelaySeconds = 10,

    [switch] $PassThru
)

$ErrorActionPreference = "Stop"

#region Embedded common authentication and service helpers
function ConvertTo-SecureM365Base64Url {
    param([Parameter(Mandatory)][byte[]] $Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function ConvertFrom-SecureM365JwtPayload {
    param([Parameter(Mandatory)][string] $Token)

    $segments = $Token.Split(".")
    if ($segments.Count -ne 3) {
        throw "Microsoft did not return a valid ID token."
    }
    $payload = $segments[1].Replace("-", "+").Replace("_", "/")
    $payload = $payload.PadRight($payload.Length + ((4 - ($payload.Length % 4)) % 4), "=")
    try {
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Microsoft returned an ID token with an invalid payload."
    }
}

function Resolve-SecureM365TenantId {
    [CmdletBinding()]
    [OutputType([guid])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $TenantId,

        [switch] $PromptIfMissing
    )

    if ([string]::IsNullOrWhiteSpace($TenantId) -and $PromptIfMissing) {
        $TenantId = Read-Host "Microsoft Entra tenant ID (GUID)"
    }

    $parsedTenantId = [guid]::Empty
    if (
        [string]::IsNullOrWhiteSpace($TenantId) -or
        -not [guid]::TryParse($TenantId, [ref] $parsedTenantId) -or
        $parsedTenantId -eq [guid]::Empty
    ) {
        throw "TenantId must be a non-empty Microsoft Entra tenant GUID."
    }
    $parsedTenantId
}

function Get-SecureM365OAuthAuthorizationCode {
    param(
        [Parameter(Mandatory)]
        [Collections.Specialized.NameValueCollection] $Query,

        [Parameter(Mandatory)]
        [string] $ExpectedState
    )

    if ($Query["state"] -cne $ExpectedState) {
        throw "OAuth state validation failed. No Graph connection was created."
    }
    if ($Query["error"]) {
        throw "Microsoft authorization failed ($($Query["error"])): $($Query["error_description"])"
    }
    if ([string]::IsNullOrWhiteSpace($Query["code"])) {
        throw "Microsoft returned no authorization code."
    }
    [string] $Query["code"]
}

function Get-SecureM365ValidatedBrowserToken {
    param(
        [Parameter(Mandatory)] $TokenResponse,
        [Parameter(Mandatory)][guid] $TenantId,
        [Parameter(Mandatory)][string[]] $Scopes,
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $Nonce
    )

    if (
        [string]::IsNullOrWhiteSpace($TokenResponse.access_token) -or
        [string]::IsNullOrWhiteSpace($TokenResponse.id_token)
    ) {
        throw "Microsoft returned an incomplete token response."
    }
    $claims = ConvertFrom-SecureM365JwtPayload $TokenResponse.id_token
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $expectedIssuer = "https://login.microsoftonline.com/$($TenantId.Guid)/v2.0"
    if (
        [string] $claims.aud -ne $ClientId -or
        [string] $claims.iss -ne $expectedIssuer -or
        [string] $claims.tid -ne $TenantId.Guid -or
        [string] $claims.nonce -cne $Nonce -or
        [long] $claims.exp -le $now
    ) {
        throw "Microsoft ID-token validation failed for the requested client, issuer, tenant, nonce, or expiry."
    }

    $grantedScopes = @([string] $TokenResponse.scope -split "\s+" | Where-Object { $_ })
    $missingScopes = @($Scopes | Where-Object { $_ -notin $grantedScopes })
    if ($missingScopes.Count -gt 0) {
        throw "Microsoft did not grant the required Graph scopes: $($missingScopes -join ', '). Review consent and retry."
    }

    [pscustomobject]@{
        AccessToken = [string] $TokenResponse.access_token
        Scopes      = $grantedScopes
        TenantId   = [string] $claims.tid
    }
}

function Invoke-SecureM365BrowserPkce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $TenantId,

        [Parameter(Mandatory)]
        [string[]] $Scopes,

        [ValidateRange(30, 900)]
        [int] $TimeoutSeconds = 180
    )

    $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $verifierBytes = [byte[]]::new(64)
        $stateBytes = [byte[]]::new(32)
        $nonceBytes = [byte[]]::new(32)
        $random.GetBytes($verifierBytes)
        $random.GetBytes($stateBytes)
        $random.GetBytes($nonceBytes)
    }
    finally {
        $random.Dispose()
    }

    $codeVerifier = ConvertTo-SecureM365Base64Url $verifierBytes
    $state = ConvertTo-SecureM365Base64Url $stateBytes
    $nonce = ConvertTo-SecureM365Base64Url $nonceBytes
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $challenge = ConvertTo-SecureM365Base64Url (
            $sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($codeVerifier))
        )
    }
    finally {
        $sha256.Dispose()
    }

    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $portProbe.Start()
    $port = ([Net.IPEndPoint] $portProbe.LocalEndpoint).Port
    $portProbe.Stop()
    $redirectUri = "http://localhost:$port/"
    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add($redirectUri)

    $authorizationParameters = [ordered]@{
        client_id             = $clientId
        response_type         = "code"
        redirect_uri          = $redirectUri
        response_mode         = "query"
        scope                 = (@("openid", "profile") + $Scopes | Sort-Object -Unique) -join " "
        state                 = $state
        nonce                 = $nonce
        code_challenge        = $challenge
        code_challenge_method = "S256"
        prompt                = "select_account"
    }
    $authorizationQuery = ($authorizationParameters.GetEnumerator() | ForEach-Object {
        "{0}={1}" -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string] $_.Value)
    }) -join "&"
    $authorizationUri =
        "https://login.microsoftonline.com/$($TenantId.Guid)/oauth2/v2.0/authorize?$authorizationQuery"

    try {
        try {
            $listener.Start()
        }
        catch {
            throw "Cannot open the local OAuth callback at '$redirectUri'. Check local listener/firewall policy and retry. $($_.Exception.Message)"
        }

        Write-Host "Opening Microsoft sign-in in your browser. Credentials are entered only on Microsoft's page."
        Write-Host "Waiting up to $TimeoutSeconds seconds for the local callback at $redirectUri"
        Start-Process $authorizationUri -ErrorAction Stop

        $contextTask = $listener.GetContextAsync()
        if (-not $contextTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            throw "Timed out waiting for Microsoft sign-in. Rerun the command and complete the browser prompt within $TimeoutSeconds seconds."
        }
        $callback = $contextTask.GetAwaiter().GetResult()
        $responseText = if (
            $callback.Request.QueryString["error"] -or
            $callback.Request.QueryString["state"] -cne $state
        ) {
            "Authentication failed. Return to the terminal for details."
        }
        else {
            "Authentication completed. You can close this window and return to the terminal."
        }
        $responseBytes = [Text.Encoding]::UTF8.GetBytes(
            "<!doctype html><html><body><p>$responseText</p></body></html>"
        )
        $callback.Response.StatusCode = 200
        $callback.Response.ContentType = "text/html; charset=utf-8"
        $callback.Response.ContentLength64 = $responseBytes.Length
        $callback.Response.OutputStream.Write($responseBytes, 0, $responseBytes.Length)
        $callback.Response.Close()

        $authorizationCode = Get-SecureM365OAuthAuthorizationCode `
            -Query $callback.Request.QueryString `
            -ExpectedState $state

        Write-Host "Browser sign-in completed. Exchanging the one-time code without storing credentials..."
        try {
            $token = Invoke-RestMethod `
                -Method POST `
                -Uri "https://login.microsoftonline.com/$($TenantId.Guid)/oauth2/v2.0/token" `
                -ContentType "application/x-www-form-urlencoded" `
                -Body @{
                    client_id     = $clientId
                    grant_type    = "authorization_code"
                    code          = $authorizationCode
                    redirect_uri  = $redirectUri
                    code_verifier = $codeVerifier
                    scope         = $authorizationParameters.scope
                } `
                -ErrorAction Stop
        }
        catch {
            throw "Microsoft token exchange failed. No credentials or tokens were saved. $($_.Exception.Message)"
        }

        Get-SecureM365ValidatedBrowserToken `
            -TokenResponse $token `
            -TenantId $TenantId `
            -Scopes $Scopes `
            -ClientId $clientId `
            -Nonce $nonce
    }
    finally {
        if ($listener.IsListening) {
            $listener.Stop()
        }
        $listener.Close()
    }
}

function Get-SecureM365GraphScopeSet {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [ValidateSet("ReadOnly", "AllScripts")]
        [string] $Profile = "ReadOnly"
    )

    $scopes = @(
        "AuditLog.Read.All"
        "Policy.Read.All"
        "RoleManagement.Read.Directory"
        "SecurityEvents.Read.All"
        "User.Read.All"
    )
    if ($Profile -eq "AllScripts") {
        $scopes += @(
            "Application.ReadWrite.All"
            "AppRoleAssignment.ReadWrite.All"
            "Directory.Read.All"
            "Domain.Read.All"
            "LicenseAssignment.Read.All"
            "Organization.Read.All"
            "Policy.ReadWrite.Authorization"
            "Policy.ReadWrite.ConditionalAccess"
            "RoleManagement.ReadWrite.Directory"
            "User.Create"
        )
    }

    [string[]] @($scopes | Sort-Object -Unique)
}

function Connect-SecureM365Graph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $TenantId,

        [string[]] $AdditionalScopes = @(),
        [switch] $UseDeviceCode,
        [switch] $UseBrowserPkce
    )

    if ($UseDeviceCode -and $UseBrowserPkce) {
        throw "UseDeviceCode and UseBrowserPkce cannot be combined."
    }

    $scopes = @(
        Get-SecureM365GraphScopeSet -Profile ReadOnly
        $AdditionalScopes
    ) | Sort-Object -Unique

    $context = Get-MgContext -ErrorAction SilentlyContinue
    $pkceMetadata = Get-Variable -Name SecureM365GraphContextMetadata -Scope Global `
        -ValueOnly -ErrorAction SilentlyContinue
    $contextTenantId = [string] $context.TenantId
    $contextScopes = @($context.Scopes)
    if (
        $null -ne $context -and
        [string] $context.AuthType -eq "UserProvidedAccessToken" -and
        $null -ne $pkceMetadata
    ) {
        if ([string]::IsNullOrWhiteSpace($contextTenantId)) {
            $contextTenantId = [string] $pkceMetadata.TenantId
        }
        if ($contextScopes.Count -eq 0) {
            $contextScopes = @($pkceMetadata.Scopes)
        }
    }
    $missingContextScopes = @($scopes | Where-Object { $_ -notin $contextScopes })
    if (
        $null -ne $context -and
        $contextTenantId -eq $TenantId.Guid -and
        [string] $context.AuthType -in @("Delegated", "UserProvidedAccessToken") -and
        [string] $context.Environment -eq "Global" -and
        $missingContextScopes.Count -eq 0
    ) {
        try {
            $existingIdentity = Invoke-MgGraphRequest `
                -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,userPrincipalName" `
                -ErrorAction Stop
            if (
                [string]::IsNullOrWhiteSpace($existingIdentity.id) -or
                [string]::IsNullOrWhiteSpace($existingIdentity.userPrincipalName)
            ) {
                throw "Graph returned an incomplete signed-in user."
            }
            if (
                [string] $context.AuthType -eq "UserProvidedAccessToken" -and
                $null -ne $pkceMetadata -and
                (
                    [string] $existingIdentity.id -ne [string] $pkceMetadata.IdentityId -or
                    [string] $existingIdentity.userPrincipalName -ne [string] $pkceMetadata.Account
                )
            ) {
                throw "The signed-in Graph user does not match the validated browser-PKCE context."
            }
            if ([string]::IsNullOrWhiteSpace([string] $context.TenantId)) {
                $context | Add-Member -NotePropertyName TenantId -NotePropertyValue $contextTenantId -Force
            }
            if (@($context.Scopes).Count -eq 0) {
                $context | Add-Member -NotePropertyName Scopes -NotePropertyValue ([string[]] $contextScopes) -Force
            }
            Write-Verbose "Reusing the existing validated Graph context for tenant '$($TenantId.Guid)'."
            return $context
        }
        catch {
            Write-Host "The existing Graph context is no longer usable; reconnecting."
        }
    }

    if (
        -not $UseDeviceCode -and -not $UseBrowserPkce -and
        $null -ne $context -and [string] $context.AuthType -eq "UserProvidedAccessToken"
    ) {
        $UseBrowserPkce = $true
        Write-Host "The existing browser-PKCE context needs additional scopes; reopening Microsoft sign-in."
    }

    $connectParameters = @{
        TenantId     = $TenantId.Guid
        Scopes       = [string[]] $scopes
        ContextScope = "Process"
        NoWelcome    = $true
        ErrorAction  = "Stop"
    }
    if ($UseBrowserPkce) {
        $pkceToken = Invoke-SecureM365BrowserPkce -TenantId $TenantId -Scopes $scopes
        $secureAccessToken = ConvertTo-SecureString $pkceToken.AccessToken -AsPlainText -Force
        $pkceToken.AccessToken = $null
        $connectParameters = @{
            AccessToken = $secureAccessToken
            NoWelcome   = $true
            ErrorAction = "Stop"
        }
    }
    elseif ($UseDeviceCode) {
        $connectParameters.UseDeviceCode = $true
    }

    Write-Host "Connecting to Microsoft Graph tenant '$($TenantId.Guid)'..."
    Connect-MgGraph @connectParameters
    $context = Get-MgContext

    if (
        $null -eq $context -or
        ($context.TenantId -and $context.TenantId -ne $TenantId.Guid) -or
        $context.AuthType -notin @("Delegated", "UserProvidedAccessToken") -or
        $context.Environment -ne "Global"
    ) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "Microsoft Graph did not connect to the intended worldwide tenant '$($TenantId.Guid)' with delegated authentication."
    }

    if ($UseBrowserPkce) {
        $contextScopes = @($pkceToken.Scopes)
    }
    else {
        $contextScopes = @($context.Scopes)
    }
    $missingScopes = @(
        $scopes |
        Where-Object { $_ -notin $contextScopes }
    )
    if ($missingScopes.Count -gt 0) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "The Graph token is missing consented scopes: $($missingScopes -join ', ')"
    }

    try {
        $identity = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,userPrincipalName" `
            -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($identity.id) -or [string]::IsNullOrWhiteSpace($identity.userPrincipalName)) {
            throw "Graph returned an incomplete signed-in user."
        }
    }
    catch {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "Microsoft Graph did not validate delegated user access for tenant '$($TenantId.Guid)'. $($_.Exception.Message)"
    }

    if ($UseBrowserPkce) {
        $context | Add-Member -NotePropertyName TenantId -NotePropertyValue $TenantId.Guid -Force
        $context | Add-Member -NotePropertyName Scopes -NotePropertyValue ([string[]] $pkceToken.Scopes) -Force
        $global:SecureM365GraphContextMetadata = [pscustomobject]@{
            TenantId   = $TenantId.Guid
            Scopes     = [string[]] $pkceToken.Scopes
            IdentityId = [string] $identity.id
            Account    = [string] $identity.userPrincipalName
        }
    }
    else {
        Remove-Variable -Name SecureM365GraphContextMetadata -Scope Global -ErrorAction SilentlyContinue
    }
    $context
}

function Get-SecureM365GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        [hashtable] $Headers = @{}
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    while ($nextLink) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -Headers $Headers -ErrorAction Stop
        if ($null -eq $page.value) {
            throw "Microsoft Graph returned no collection value for '$nextLink'."
        }
        foreach ($item in @($page.value)) {
            [void] $items.Add($item)
        }
        $nextLink = $page.'@odata.nextLink'
    }

    $items.ToArray()
}

function Get-SecureM365TeamsMeetingPolicy {
    [CmdletBinding()]
    param()

    $policies = @(Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop)
    if ($policies.Count -ne 1) {
        throw "Teams must return exactly one Global meeting policy, but returned $($policies.Count)."
    }
    if ([string] $policies[0].Identity -ne "Global") {
        throw "Teams returned meeting policy identity '$($policies[0].Identity)' when Global was requested."
    }
    $policies[0]
}

function Connect-SecureM365Teams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid] $TenantId,
        [Parameter(Mandatory)][guid] $ApplicationId,
        [Parameter(Mandatory)][string] $CertificateThumbprint
    )

    if ($TenantId -eq [guid]::Empty -or $ApplicationId -eq [guid]::Empty) {
        throw "Teams requires non-empty tenant and application IDs."
    }
    $normalizedThumbprint = $CertificateThumbprint -replace '\s', ''
    if ($normalizedThumbprint -notmatch '^[0-9A-Fa-f]{40,128}$') {
        throw "CertificateThumbprint must contain only hexadecimal characters."
    }
    $connection = Connect-MicrosoftTeams -TenantId $TenantId.Guid `
        -ApplicationId $ApplicationId.Guid -CertificateThumbprint $normalizedThumbprint -ErrorAction Stop
    if ([string] $connection.TenantId -ne $TenantId.Guid) {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
        throw "Microsoft Teams connected to tenant '$($connection.TenantId)' instead of '$($TenantId.Guid)'."
    }
    $null = Get-SecureM365TeamsMeetingPolicy
    $connection
}

function New-SecureM365ConditionalAccessPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $BodyParameter
    )

    $existingPolicies = @(
        Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
        Where-Object { $_.DisplayName -eq $BodyParameter.displayName }
    )
    if ($existingPolicies.Count -gt 0) {
        $existingIds = $existingPolicies.Id -join ", "
        throw "A policy named '$($BodyParameter.displayName)' already exists ($existingIds). Review it instead of creating a duplicate."
    }

    New-MgIdentityConditionalAccessPolicy `
        -BodyParameter $BodyParameter `
        -ErrorAction Stop
}
#endregion

#region Emergency credential protection from script 04
function Get-SecurePasswordFingerprint {
    param(
        [Parameter(Mandatory)]
        [securestring] $SecurePassword
    )

    $plainPassword = $null
    $passwordBytes = $null
    try {
        $plainPassword = [System.Net.NetworkCredential]::new("", $SecurePassword).Password
        $passwordBytes = [Text.Encoding]::UTF8.GetBytes($plainPassword)
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($passwordBytes))
    }
    finally {
        if ($null -ne $passwordBytes) {
            [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
        }
        $plainPassword = $null
    }
}

function New-EmergencyPassword {
    [OutputType([securestring])]
    param()

    [string[]] $categories = @(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!#$%&()*+,-./:;<=>?@[]^_{|}~"
    )
    $allCharacters = [char[]] (($categories | ForEach-Object { -join $_ }) -join "")
    $characters = [char[]]::new(48)
    try {
        for ($index = 0; $index -lt $categories.Count; $index++) {
            $characters[$index] = $categories[$index][
                [Security.Cryptography.RandomNumberGenerator]::GetInt32($categories[$index].Count)
            ]
        }
        for ($index = $categories.Count; $index -lt $characters.Count; $index++) {
            $characters[$index] = $allCharacters[
                [Security.Cryptography.RandomNumberGenerator]::GetInt32($allCharacters.Count)
            ]
        }
        for ($index = $characters.Count - 1; $index -gt 0; $index--) {
            $swapIndex = [Security.Cryptography.RandomNumberGenerator]::GetInt32($index + 1)
            ($characters[$index], $characters[$swapIndex]) = (
                $characters[$swapIndex], $characters[$index]
            )
        }

        $securePassword = [securestring]::new()
        foreach ($character in $characters) {
            $securePassword.AppendChar($character)
        }
        $securePassword.MakeReadOnly()
        $securePassword
    }
    finally {
        [Array]::Clear($characters, 0, $characters.Length)
        [Array]::Clear($allCharacters, 0, $allCharacters.Length)
    }
}

function Save-EmergencyPasswordArtifact {
    param(
        [Parameter(Mandatory)]
        [guid] $ArtifactTenantId,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Passwords,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Fingerprints,

        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $Overwrite
    )

    if (Test-Path -LiteralPath $Path -PathType Container) {
        throw "PasswordFilePath '$Path' is a directory. Supply a file path."
    }
    if ((Test-Path -LiteralPath $Path) -and -not $Overwrite) {
        throw "Password file '$Path' already exists. No accounts were created. Use OverwritePasswordFile only after confirming that replacement is intended."
    }

    $directory = [IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrWhiteSpace($directory)) {
        throw "PasswordFilePath must include a parent directory."
    }
    [void] [IO.Directory]::CreateDirectory($directory)

    $temporaryPath = Join-Path $directory ".$([IO.Path]::GetRandomFileName()).tmp"
    try {
        $entries = @(
            foreach ($upn in ($Passwords.Keys | Sort-Object)) {
                [ordered]@{
                    userPrincipalName = $upn
                    encryptedPassword = ConvertFrom-SecureString $Passwords[$upn]
                }
            }
        )
        $artifact = [ordered]@{
            schemaVersion = 1
            protection = "WindowsUserDpapiSecureString"
            tenantId = $ArtifactTenantId.Guid
            createdAtUtc = [DateTimeOffset]::UtcNow.ToString("o")
            accounts = $entries
        }
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($artifact | ConvertTo-Json -Depth 4),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force:$Overwrite

        $persistedArtifact = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if (
            $persistedArtifact.schemaVersion -ne 1 -or
            $persistedArtifact.protection -ne "WindowsUserDpapiSecureString" -or
            $persistedArtifact.tenantId -ne $ArtifactTenantId.Guid -or
            @($persistedArtifact.accounts).Count -ne $Passwords.Count
        ) {
            throw "Password file '$Path' failed metadata verification. No accounts were created."
        }
        foreach ($entry in @($persistedArtifact.accounts)) {
            if (
                [string]::IsNullOrWhiteSpace($entry.userPrincipalName) -or
                -not $Passwords.Contains($entry.userPrincipalName) -or
                [string]::IsNullOrWhiteSpace($entry.encryptedPassword)
            ) {
                throw "Password file '$Path' contains an unexpected or incomplete account entry. No accounts were created."
            }
            $recoveredPassword = $null
            try {
                $recoveredPassword = ConvertTo-SecureString $entry.encryptedPassword
                if (
                    (Get-SecurePasswordFingerprint $recoveredPassword) -ne
                    $Fingerprints[$entry.userPrincipalName]
                ) {
                    throw "Password file '$Path' failed recovery verification for '$($entry.userPrincipalName)'. No accounts were created."
                }
            }
            finally {
                if ($null -ne $recoveredPassword) {
                    $recoveredPassword.Dispose()
                }
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}
#endregion

#region Discovery and matching safeguards
function ConvertTo-SecureM365ObjectId {
    param([AllowNull()][AllowEmptyString()][string] $Value, [string] $Label)
    $id = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref] $id) -or $id -eq [guid]::Empty) {
        throw "$Label did not contain a non-empty object GUID."
    }
    $id.Guid
}

function Test-SecureM365Property {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [Collections.IDictionary]) { return $Object.Contains($Name) }
    $null -ne $Object.PSObject.Properties[$Name]
}

function ConvertTo-SecureM365ComparableJson {
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) {
        if ($Value.Length -eq 0) { return "" }
        return ConvertTo-Json -InputObject $Value.ToLowerInvariant() -Compress
    }
    if ($Value -is [bool]) {
        if (-not $Value) { return "" }
        return "true"
    }
    if ($Value -is [Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $names = if ($Value -is [Collections.IDictionary]) {
            @($Value.Keys)
        }
        else {
            @($Value.PSObject.Properties.Name)
        }
        $properties = @(
            foreach ($name in ($names | Sort-Object)) {
                # Graph annotates properties too, for example authenticationStrength@odata.context.
                if ($name -like "*@odata.*") { continue }
                $child = $Value.$name
                # Graph can expand strength metadata; the built-in ID defines the grant.
                if ($name -eq "authenticationStrength" -and $null -ne $child) {
                    $child = @{ id = $child.id }
                }
                $normalized = ConvertTo-SecureM365ComparableJson $child
                if ($normalized.Length -gt 0) {
                    (ConvertTo-Json -InputObject $name.ToLowerInvariant() -Compress) + ":" + $normalized
                }
            }
        )
        if ($properties.Count -eq 0) { return "" }
        return "{" + ($properties -join ",") + "}"
    }
    if ($Value -is [Collections.IEnumerable]) {
        $items = @(
            foreach ($item in $Value) {
                $normalized = ConvertTo-SecureM365ComparableJson $item
                if ($normalized.Length -gt 0) { $normalized }
            }
        ) | Sort-Object -Unique
        if (@($items).Count -eq 0) { return "" }
        return "[" + ($items -join ",") + "]"
    }
    ConvertTo-Json -InputObject $Value -Compress -Depth 20
}

function Assert-SecureM365PolicyMatch {
    param([Parameter(Mandatory)] $Policy, [Parameter(Mandatory)][hashtable] $Body)

    $null = ConvertTo-SecureM365ObjectId $Policy.id "Conditional Access policy '$($Body.displayName)'"
    if ($Policy.displayName -ne $Body.displayName) {
        throw "The requested Conditional Access policy identity changed. No existing policy will be overwritten."
    }
    if ($Policy.state -notin @("enabled", "enabledForReportingButNotEnforced")) {
        throw "Policy '$($Policy.displayName)' is '$($Policy.state)', not enabled or report-only. Review it manually before rerunning."
    }
    foreach ($field in @("conditions", "grantControls", "sessionControls")) {
        $expected = ConvertTo-SecureM365ComparableJson $Body[$field]
        $actual = ConvertTo-SecureM365ComparableJson $Policy.$field
        if ($actual -cne $expected) {
            throw "Policy '$($Policy.displayName)' ($($Policy.id)) differs in $field. Expected (normalized): $expected. Actual (normalized): $actual. Existing policies are not rewritten; review the difference before rerunning."
        }
    }
}

function Wait-SecureM365Propagation {
    param([string] $Operation, [int] $Attempt)
    Write-Warning "$Operation is not verified yet; waiting $PropagationRetryDelaySeconds seconds (attempt $Attempt of $PropagationRetryCount)."
    if ($PropagationRetryDelaySeconds -gt 0) {
        Start-Sleep -Seconds $PropagationRetryDelaySeconds
    }
}

function Get-ReviewedConditionalAccessPolicy {
    param(
        [Parameter(Mandatory)][guid] $PolicyId,
        [ValidateSet("enabled", "enabledForReportingButNotEnforced")][string] $ExpectedState
    )

    foreach ($attempt in 1..$PropagationRetryCount) {
        try {
            $policy = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($PolicyId.Guid)" `
                -Headers @{ Prefer = "include-unknown-enum-members" } -ErrorAction Stop
            if ([string] $policy.id -ne $PolicyId.Guid) {
                throw "Conditional Access readback did not return policy '$($PolicyId.Guid)'."
            }
            if (-not $ExpectedState -or $policy.state -eq $ExpectedState) {
                return $policy
            }
            if ($attempt -eq $PropagationRetryCount) {
                throw "Policy '$($policy.displayName)' remains '$($policy.state)'; expected '$ExpectedState'."
            }
        }
        catch {
            # REST requests expose Response.StatusCode; generated Graph cmdlets use ResponseStatusCode.
            $statusCode = $_.Exception.Response.StatusCode
            if ($null -eq $statusCode) { $statusCode = $_.Exception.ResponseStatusCode }
            if ($null -eq $statusCode) { $statusCode = $_.Exception.StatusCode }
            $notFound = if ($null -ne $statusCode) {
                [string] $statusCode -in @("NotFound", "404")
            }
            else {
                $details = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
                $details -match '(?i)\b404\b|\bNot\s*Found\b|ResourceNotFound|does not exist in the directory'
            }
            if (-not $notFound -or $attempt -eq $PropagationRetryCount) { throw }
        }
        Wait-SecureM365Propagation -Operation "Policy '$($PolicyId.Guid)' readback" -Attempt $attempt
    }
}

function Assert-SecureM365SecurityDefaultsDisabled {
    $policy = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -ErrorAction Stop
    if ($policy.isEnabled -isnot [bool]) {
        throw "Security Defaults did not return a Boolean isEnabled value; configuration cannot safely continue."
    }
    if ($policy.isEnabled) {
        throw "Security Defaults is enabled. The original configuration scripts assume it is disabled. Plan and complete that transition explicitly, then rerun; this script will not disable it."
    }
}

function Get-SecureM365EmergencyAccountPlan {
    param(
        [Parameter(Mandatory)][string] $Domain,
        [Parameter(Mandatory)][string] $GlobalAdministratorRoleId,
        [Parameter(Mandatory)][string[]] $Names
    )

    foreach ($name in $Names) {
        $upn = "$name@$Domain"
        $filter = [uri]::EscapeDataString("userPrincipalName eq '$upn'")
        $users = @(Get-SecureM365GraphCollection `
            -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=id,userPrincipalName,displayName,mailNickname,accountEnabled,userType,passwordPolicies,onPremisesSyncEnabled,onPremisesImmutableId")
        if ($users.Count -gt 1) {
            throw "User '$upn' is ambiguous. No existing account will be modified."
        }
        $result = [pscustomobject]@{
            Name = $name
            DisplayName = "Emergency access - $name"
            UserPrincipalName = $upn
            Id = $null
            RoleAssignmentId = $null
            Action = "Create"
        }
        if ($users.Count -eq 1) {
            $user = $users[0]
            $userId = ConvertTo-SecureM365ObjectId $user.id "Emergency account '$upn'"
            if (
                $user.userPrincipalName -ne $upn -or
                $user.displayName -ne $result.DisplayName -or
                $user.mailNickname -ne $name -or
                $user.accountEnabled -isnot [bool] -or -not $user.accountEnabled -or
                $user.userType -ne "Member" -or
                -not (Test-SecureM365Property $user "onPremisesSyncEnabled") -or
                ($null -ne $user.onPremisesSyncEnabled -and $user.onPremisesSyncEnabled -isnot [bool]) -or
                $user.onPremisesSyncEnabled -eq $true -or
                -not (Test-SecureM365Property $user "onPremisesImmutableId") -or
                -not [string]::IsNullOrWhiteSpace([string] $user.onPremisesImmutableId) -or
                ([string] $user.passwordPolicies).Trim() -ne "DisablePasswordExpiration"
            ) {
                throw "Existing account '$upn' does not match script 04's enabled, cloud-only emergency-account settings. It will not be reset, elevated, or changed."
            }

            $principalFilter = [uri]::EscapeDataString("principalId eq '$userId'")
            $assignments = @(Get-SecureM365GraphCollection `
                -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$principalFilter&`$select=id,principalId,roleDefinitionId,directoryScopeId")
            $globalAssignments = @($assignments | Where-Object {
                $_.principalId -eq $userId -and $_.roleDefinitionId -eq $GlobalAdministratorRoleId -and
                $_.directoryScopeId -eq "/" -and -not [string]::IsNullOrWhiteSpace([string] $_.id)
            })
            if ($globalAssignments.Count -ne 1) {
                throw "Existing account '$upn' must already have exactly one direct, tenant-wide Global Administrator assignment. Existing users are never elevated."
            }
            $instances = @(Get-SecureM365GraphCollection `
                -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=$principalFilter&`$select=id,principalId,roleDefinitionId,directoryScopeId,assignmentType,memberType,startDateTime,endDateTime,roleAssignmentOriginId")
            $permanent = @($instances | Where-Object {
                $_.principalId -eq $userId -and $_.roleDefinitionId -eq $GlobalAdministratorRoleId -and
                $_.directoryScopeId -eq "/" -and $_.assignmentType -eq "Assigned" -and
                $_.memberType -eq "Direct" -and
                $_.roleAssignmentOriginId -ceq $globalAssignments[0].id -and
                (Test-SecureM365Property $_ "endDateTime") -and $null -eq $_.endDateTime -and
                ($null -eq $_.startDateTime -or [datetimeoffset] $_.startDateTime -le [datetimeoffset]::UtcNow)
            })
            if ($permanent.Count -ne 1) {
                throw "The Global Administrator assignment for '$upn' could not be verified as permanent and active. PIM activation/eligibility is not sufficient for this emergency-account configuration."
            }
            $result.Id = $userId
            $result.RoleAssignmentId = [string] $globalAssignments[0].id
            $result.Action = "Reuse"
        }
        $result
    }
}

function Assert-SecureM365TeamsCertificate {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    if (
        -not $Certificate.HasPrivateKey -or $Certificate.NotBefore -gt (Get-Date) -or
        $Certificate.NotAfter -le (Get-Date) -or
        $Certificate.SignatureAlgorithm.Value -ne "1.2.840.113549.1.1.11"
    ) {
        throw "The Teams certificate must be currently valid, SHA256/RSA-signed, and have an accessible private key."
    }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -ne 3072) {
            throw "The Teams certificate must have script 06's 3072-bit RSA key."
        }
        $nonExportable = if ($rsa -is [Security.Cryptography.RSACng]) {
            $rsa.Key.ExportPolicy -eq [Security.Cryptography.CngExportPolicies]::None
        }
        elseif ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            -not $rsa.CspKeyContainerInfo.Exportable
        }
        else {
            $false
        }
        if (-not $nonExportable) {
            throw "The Teams certificate's private key could not be verified as non-exportable."
        }
    }
    finally {
        if ($null -ne $rsa) { $rsa.Dispose() }
    }
}

function Get-SecureM365TeamsApplicationPlan {
    param(
        [Parameter(Mandatory)][string] $DisplayName,
        [Parameter(Mandatory)][string] $CertificateSubject,
        [Parameter(Mandatory)][string] $GraphServicePrincipalId,
        [Parameter(Mandatory)][string] $OrganizationReadRoleId,
        [Parameter(Mandatory)][string] $TeamsRoleDefinitionId
    )

    $escapedName = [uri]::EscapeDataString($DisplayName.Replace("'", "''"))
    $applications = @(Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName%20eq%20'$escapedName'&`$select=id,appId,displayName")
    $certificates = @(Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop |
        Where-Object Subject -eq $CertificateSubject)
    if ($applications.Count -gt 1 -or $certificates.Count -gt 1) {
        throw "The Teams application name or certificate subject is ambiguous. Resolve duplicates manually."
    }
    $result = [pscustomobject]@{
        Action = "Create"
        ApplicationDisplayName = $DisplayName
        ApplicationId = $null
        ApplicationObjectId = $null
        ServicePrincipalObjectId = $null
        CertificateSubject = $CertificateSubject
        CertificateThumbprint = $null
        CertificateNotAfter = $null
        GraphServicePrincipalId = $GraphServicePrincipalId
        OrganizationReadRoleId = $OrganizationReadRoleId
        TeamsRoleDefinitionId = $TeamsRoleDefinitionId
        AppRoleAssignmentId = $null
        DirectoryRoleAssignmentId = $null
    }
    if ($applications.Count -eq 0 -and $certificates.Count -eq 0) { return $result }
    if ($applications.Count -ne 1 -or $certificates.Count -ne 1) {
        throw "Only part of the Teams application/certificate setup exists. Review the application and Cert:\CurrentUser\My; partial identities are not silently repaired or replaced."
    }

    $applicationObjectId = ConvertTo-SecureM365ObjectId $applications[0].id "Teams application object"
    $application = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/applications/${applicationObjectId}?`$select=id,appId,displayName,signInAudience,keyCredentials,passwordCredentials,requiredResourceAccess" -ErrorAction Stop
    $applicationId = ConvertTo-SecureM365ObjectId $application.appId "Teams application client ID"
    if (
        $application.id -ne $applicationObjectId -or $application.displayName -ne $DisplayName -or
        $application.signInAudience -ne "AzureADMyOrg" -or
        -not (Test-SecureM365Property $application "passwordCredentials") -or
        @($application.passwordCredentials | Where-Object { $null -ne $_ }).Count -ne 0
    ) {
        throw "The existing Teams application is not the expected single-tenant, certificate-only application."
    }
    $requiredAccess = @(@{
        resourceAppId = "00000003-0000-0000-c000-000000000000"
        resourceAccess = @(@{ id = $OrganizationReadRoleId; type = "Role" })
    })
    if ((ConvertTo-SecureM365ComparableJson $application.requiredResourceAccess) -cne
        (ConvertTo-SecureM365ComparableJson $requiredAccess)) {
        throw "The existing Teams application's requested permissions differ from Organization.Read.All only."
    }
    $certificate = $certificates[0]
    Assert-SecureM365TeamsCertificate -Certificate $certificate
    $keys = @($application.keyCredentials)
    if (
        $keys.Count -ne 1 -or $keys[0].type -ne "AsymmetricX509Cert" -or
        $keys[0].usage -ne "Verify" -or
        [string] $keys[0].key -cne [Convert]::ToBase64String($certificate.RawData) -or
        [string]::IsNullOrWhiteSpace([string] $keys[0].startDateTime) -or
        [string]::IsNullOrWhiteSpace([string] $keys[0].endDateTime) -or
        [datetimeoffset] $keys[0].startDateTime -gt [datetimeoffset]::UtcNow -or
        [datetimeoffset] $keys[0].endDateTime -le [datetimeoffset]::UtcNow
    ) {
        throw "The Teams application's public certificate does not uniquely match the valid local certificate. No key will be rotated."
    }
    $servicePrincipals = @(Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'$applicationId'&`$select=id,appId,accountEnabled,passwordCredentials")
    if ($servicePrincipals.Count -ne 1 -or $servicePrincipals[0].appId -ne $applicationId -or
        $servicePrincipals[0].accountEnabled -isnot [bool] -or -not $servicePrincipals[0].accountEnabled -or
        -not (Test-SecureM365Property $servicePrincipals[0] "passwordCredentials") -or
        @($servicePrincipals[0].passwordCredentials | Where-Object { $null -ne $_ }).Count -ne 0) {
        throw "The Teams application must have exactly one enabled, matching service principal without client secrets."
    }
    $principalId = ConvertTo-SecureM365ObjectId $servicePrincipals[0].id "Teams service principal"
    $appGrants = @(Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments")
    if (
        $appGrants.Count -ne 1 -or $appGrants[0].principalId -ne $principalId -or
        $appGrants[0].resourceId -ne $GraphServicePrincipalId -or
        $appGrants[0].appRoleId -ne $OrganizationReadRoleId -or
        [string]::IsNullOrWhiteSpace([string] $appGrants[0].id)
    ) {
        throw "The Teams service principal's application grants do not match Organization.Read.All only."
    }
    $filter = [uri]::EscapeDataString("principalId eq '$principalId'")
    $directoryGrants = @(Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$filter&`$select=id,principalId,roleDefinitionId,directoryScopeId")
    if (
        $directoryGrants.Count -ne 1 -or $directoryGrants[0].principalId -ne $principalId -or
        $directoryGrants[0].roleDefinitionId -ne $TeamsRoleDefinitionId -or
        $directoryGrants[0].directoryScopeId -ne "/" -or
        [string]::IsNullOrWhiteSpace([string] $directoryGrants[0].id)
    ) {
        throw "The Teams service principal's directory roles do not match tenant-wide Teams Communications Administrator only."
    }
    $result.Action = "Reuse"
    $result.ApplicationId = $applicationId
    $result.ApplicationObjectId = $applicationObjectId
    $result.ServicePrincipalObjectId = $principalId
    $result.CertificateThumbprint = $certificate.Thumbprint
    $result.CertificateNotAfter = $certificate.NotAfter
    $result.AppRoleAssignmentId = [string] $appGrants[0].id
    $result.DirectoryRoleAssignmentId = [string] $directoryGrants[0].id
    $result
}

function Get-SecureM365ConfigurationPolicyBodies {
    param(
        [string[]] $AdminRoleTemplateId,
        [guid[]] $EmergencyAccessAccountId = @(),
        [guid[]] $TemporaryExceptionAccountId = @()
    )

    @{
        displayName = "CA001 - Require MFA for administrator roles"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = @("all")
            applications = @{ includeApplications = @("All"); excludeApplications = @() }
            users = @{ includeRoles = $AdminRoleTemplateId; excludeUsers = @($EmergencyAccessAccountId.Guid) }
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    }
    @{
        displayName = "CA002 - Require MFA for all users"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = @("all")
            applications = @{ includeApplications = @("All"); excludeApplications = @() }
            users = @{ includeUsers = @("All"); excludeUsers = @($EmergencyAccessAccountId.Guid) }
        }
        grantControls = @{
            operator = "OR"
            authenticationStrength = @{ id = "00000000-0000-0000-0000-000000000002" }
        }
    }
    @{
        displayName = "CA003 - Block legacy authentication"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = @("exchangeActiveSync", "other")
            applications = @{ includeApplications = @("All"); excludeApplications = @() }
            users = @{
                includeUsers = @("All")
                excludeUsers = @($TemporaryExceptionAccountId | ForEach-Object { $_.Guid })
            }
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }
    @{
        displayName = "CA004 - Require MFA for medium and high sign-in risk"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = @("all")
            signInRiskLevels = @("medium", "high")
            applications = @{ includeApplications = @("All"); excludeApplications = @() }
            users = @{ includeUsers = @("All"); excludeUsers = @($EmergencyAccessAccountId.Guid) }
        }
        grantControls = @{
            operator = "OR"
            authenticationStrength = @{ id = "00000000-0000-0000-0000-000000000002" }
        }
        sessionControls = @{
            signInFrequency = @{
                isEnabled = $true
                frequencyInterval = "everyTime"
                authenticationType = "primaryAndSecondaryAuthentication"
            }
        }
    }
    @{
        displayName = "CA005 - Require remediation for high user risk"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = @("all")
            userRiskLevels = @("high")
            applications = @{ includeApplications = @("All"); excludeApplications = @() }
            users = @{ includeUsers = @("All"); excludeUsers = @($EmergencyAccessAccountId.Guid) }
        }
        grantControls = @{
            operator = "AND"
            builtInControls = @("passwordChange")
            authenticationStrength = @{ id = "00000000-0000-0000-0000-000000000002" }
        }
        sessionControls = @{
            signInFrequency = @{
                isEnabled = $true
                frequencyInterval = "everyTime"
                authenticationType = "primaryAndSecondaryAuthentication"
            }
        }
    }
}

function Get-SecureM365UserConsentAssignments {
    $policies = @(Get-MgPolicyAuthorizationPolicy -ErrorAction Stop)
    if ($policies.Count -ne 1 -or
        $null -eq $policies[0].DefaultUserRolePermissions.PermissionGrantPoliciesAssigned) {
        throw "Authorization policy did not return exactly one readable permissionGrantPoliciesAssigned collection."
    }
    foreach ($assignment in $policies[0].DefaultUserRolePermissions.PermissionGrantPoliciesAssigned) {
        if ($assignment -isnot [string] -or [string]::IsNullOrWhiteSpace($assignment)) {
            throw "Authorization policy returned an invalid permission-grant assignment."
        }
        $assignment
    }
}
#endregion

#region Configuration operations
function New-SecureM365EmergencyAccounts {
    param(
        [Parameter(Mandatory)][guid] $TenantId,
        [Parameter(Mandatory)][object[]] $Plans,
        [Parameter(Mandatory)][string] $RoleDefinitionId,
        [string] $Path,
        [switch] $Overwrite,
        [Parameter(Mandatory)][hashtable] $RunState
    )

    $newAccounts = @($Plans | Where-Object Action -eq "Create")
    if ($newAccounts.Count -eq 0) { return $Plans }
    $passwords = @{}
    $fingerprints = @{}
    try {
        foreach ($account in $newAccounts) {
            $upn = $account.UserPrincipalName
            do {
                if ($passwords.Contains($upn)) { $passwords[$upn].Dispose() }
                $passwords[$upn] = New-EmergencyPassword
                $fingerprints[$upn] = Get-SecurePasswordFingerprint $passwords[$upn]
            } while (@($fingerprints.GetEnumerator() | Where-Object {
                $_.Key -ne $upn -and $_.Value -eq $fingerprints[$upn]
            }).Count -gt 0)
        }
        $RunState.CurrentOperation = "Save and verify emergency passwords in '$Path'"
        Save-EmergencyPasswordArtifact -ArtifactTenantId $TenantId -Passwords $passwords `
            -Fingerprints $fingerprints -Path $Path -Overwrite:$Overwrite
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Password artifact"; Action = "Saved"; Id = $Path; Name = $TenantId.Guid
        })
        Write-Warning "New emergency passwords were saved and recovery-verified in '$Path'. Only this Windows user on this computer can decrypt the DPAPI artifact. Keep a protected backup."

        foreach ($account in $newAccounts) {
            $upn = $account.UserPrincipalName
            $filter = [uri]::EscapeDataString("userPrincipalName eq '$upn'")
            $collision = @(Get-SecureM365GraphCollection `
                -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=id,userPrincipalName")
            if ($collision.Count -gt 0) {
                throw "Account '$upn' appeared after preflight. It will not be reset or elevated; review it before retrying."
            }
            $body = @{
                accountEnabled = $true
                displayName = $account.DisplayName
                mailNickname = $account.Name
                userPrincipalName = $upn
                userType = "Member"
                passwordPolicies = "DisablePasswordExpiration"
                passwordProfile = @{
                    forceChangePasswordNextSignIn = $false
                    password = [Net.NetworkCredential]::new("", $passwords[$upn]).Password
                }
            }
            $json = $null
            try {
                $RunState.CurrentOperation = "Create emergency account '$upn'"
                $json = $body | ConvertTo-Json -Depth 4
                $user = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users" `
                    -Body $json -ContentType "application/json" -Debug:$false -Verbose:$false -ErrorAction Stop
            }
            finally {
                $body.passwordProfile.password = $null
                $json = $null
            }
            $id = ConvertTo-SecureM365ObjectId $user.id "New emergency account '$upn'"
            [void] $RunState.Changes.Add([pscustomobject]@{
                Resource = "User"; Action = "Created"; Id = $id; Name = [string] $user.userPrincipalName
            })
            if ($user.userPrincipalName -ne $upn) {
                throw "Graph returned '$($user.userPrincipalName)' ($id) instead of '$upn'. No role was assigned."
            }
            $account.Id = $id
            $RunState.CurrentOperation = "Assign permanent Global Administrator to '$upn' ($id)"
            $assignment = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
                -Body (@{ principalId = $id; roleDefinitionId = $RoleDefinitionId; directoryScopeId = "/" } | ConvertTo-Json) `
                -ContentType "application/json" -ErrorAction Stop
            if (
                [string]::IsNullOrWhiteSpace([string] $assignment.id) -or
                $assignment.principalId -ne $id -or $assignment.roleDefinitionId -ne $RoleDefinitionId -or
                $assignment.directoryScopeId -ne "/"
            ) {
                throw "The permanent Global Administrator assignment for '$upn' ($id) was not confirmed."
            }
            $account.RoleAssignmentId = [string] $assignment.id
            $account.Action = "Created"
            [void] $RunState.Changes.Add([pscustomobject]@{
                Resource = "Directory role assignment"; Action = "Created"; Id = $assignment.id; Name = $upn
            })
        }
        $Plans
    }
    finally {
        foreach ($password in $passwords.Values) { $password.Dispose() }
        $passwords.Clear()
        $fingerprints.Clear()
    }
}

function New-SecureM365TeamsApplication {
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)][hashtable] $RunState
    )

    if ($Plan.Action -eq "Reuse") { return $Plan }
    $current = Get-SecureM365TeamsApplicationPlan -DisplayName $Plan.ApplicationDisplayName `
        -CertificateSubject $Plan.CertificateSubject -GraphServicePrincipalId $Plan.GraphServicePrincipalId `
        -OrganizationReadRoleId $Plan.OrganizationReadRoleId -TeamsRoleDefinitionId $Plan.TeamsRoleDefinitionId
    if ($current.Action -ne "Create") {
        throw "The Teams application or certificate appeared after preflight. Review the identity before retrying."
    }
    $certificate = $null
    try {
        $RunState.CurrentOperation = "Create non-exportable Teams certificate '$($Plan.CertificateSubject)'"
        $certificate = New-SelfSignedCertificate -Subject $Plan.CertificateSubject `
            -CertStoreLocation "Cert:\CurrentUser\My" -KeyAlgorithm RSA -KeyLength 3072 `
            -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeySpec Signature `
            -NotAfter (Get-Date).AddMonths($CertificateValidityMonths) -ErrorAction Stop
        $Plan.CertificateThumbprint = $certificate.Thumbprint
        $Plan.CertificateNotAfter = $certificate.NotAfter
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Certificate"; Action = "Created"; Id = $certificate.Thumbprint; Name = $Plan.CertificateSubject
        })
        Assert-SecureM365TeamsCertificate -Certificate $certificate
        if ($certificate.Subject -ne $Plan.CertificateSubject) {
            throw "The generated certificate subject does not match the requested Teams identity."
        }
        $body = @{
            displayName = $Plan.ApplicationDisplayName
            signInAudience = "AzureADMyOrg"
            keyCredentials = @(@{
                type = "AsymmetricX509Cert"
                usage = "Verify"
                keyId = [guid]::NewGuid().Guid
                displayName = $Plan.CertificateSubject
                startDateTime = $certificate.NotBefore.ToUniversalTime().ToString("o")
                endDateTime = $certificate.NotAfter.ToUniversalTime().ToString("o")
                key = [Convert]::ToBase64String($certificate.RawData)
            })
            requiredResourceAccess = @(@{
                resourceAppId = "00000003-0000-0000-c000-000000000000"
                resourceAccess = @(@{ id = $Plan.OrganizationReadRoleId; type = "Role" })
            })
        }
        $RunState.CurrentOperation = "Create Teams application '$($Plan.ApplicationDisplayName)'"
        $application = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications" `
            -Body ($body | ConvertTo-Json -Depth 8) -ContentType "application/json" -ErrorAction Stop
        $Plan.ApplicationObjectId = ConvertTo-SecureM365ObjectId $application.id "New Teams application object"
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Application"; Action = "Created"; Id = $Plan.ApplicationObjectId; Name = $Plan.ApplicationDisplayName
        })
        $Plan.ApplicationId = ConvertTo-SecureM365ObjectId $application.appId "New Teams application client ID"

        $RunState.CurrentOperation = "Create Teams service principal for '$($Plan.ApplicationId)'"
        $principal = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
            -Body (@{ appId = $Plan.ApplicationId } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
        $Plan.ServicePrincipalObjectId = ConvertTo-SecureM365ObjectId $principal.id "New Teams service principal"
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Service principal"; Action = "Created"; Id = $Plan.ServicePrincipalObjectId; Name = $Plan.ApplicationId
        })
        if ($principal.appId -ne $Plan.ApplicationId) {
            throw "Graph returned a service principal for a different application. No permissions were assigned to it."
        }
        $RunState.CurrentOperation = "Grant Organization.Read.All to Teams service principal '$($Plan.ServicePrincipalObjectId)'"
        $appGrant = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($Plan.ServicePrincipalObjectId)/appRoleAssignments" `
            -Body (@{
                principalId = $Plan.ServicePrincipalObjectId
                resourceId = $Plan.GraphServicePrincipalId
                appRoleId = $Plan.OrganizationReadRoleId
            } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
        if (
            [string]::IsNullOrWhiteSpace([string] $appGrant.id) -or
            $appGrant.principalId -ne $Plan.ServicePrincipalObjectId -or
            $appGrant.resourceId -ne $Plan.GraphServicePrincipalId -or
            $appGrant.appRoleId -ne $Plan.OrganizationReadRoleId
        ) {
            throw "The Teams Organization.Read.All application grant was not confirmed."
        }
        $Plan.AppRoleAssignmentId = [string] $appGrant.id
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Application permission"; Action = "Granted"; Id = $appGrant.id; Name = "Organization.Read.All"
        })
        $RunState.CurrentOperation = "Assign Teams Communications Administrator to '$($Plan.ServicePrincipalObjectId)'"
        $roleGrant = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
            -Body (@{
                principalId = $Plan.ServicePrincipalObjectId
                roleDefinitionId = $Plan.TeamsRoleDefinitionId
                directoryScopeId = "/"
            } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
        if (
            [string]::IsNullOrWhiteSpace([string] $roleGrant.id) -or
            $roleGrant.principalId -ne $Plan.ServicePrincipalObjectId -or
            $roleGrant.roleDefinitionId -ne $Plan.TeamsRoleDefinitionId -or
            $roleGrant.directoryScopeId -ne "/"
        ) {
            throw "The Teams Communications Administrator assignment was not confirmed."
        }
        $Plan.DirectoryRoleAssignmentId = [string] $roleGrant.id
        $Plan.Action = "Created"
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Directory role assignment"; Action = "Created"; Id = $roleGrant.id; Name = "Teams Communications Administrator"
        })
        $Plan
    }
    finally {
        if ($null -ne $certificate) { $certificate.Dispose() }
    }
}

function Connect-SecureM365ConfiguredTeams {
    param([Parameter(Mandatory)][guid] $TenantId, [Parameter(Mandatory)] $Application)
    foreach ($attempt in 1..$PropagationRetryCount) {
        try {
            return Connect-SecureM365Teams -TenantId $TenantId `
                -ApplicationId $Application.ApplicationId -CertificateThumbprint $Application.CertificateThumbprint
        }
        catch {
            Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
            if ($attempt -eq $PropagationRetryCount) {
                throw [InvalidOperationException]::new(
                    "Teams certificate access could not be verified. Review Organization.Read.All, the active Teams Communications Administrator assignment, and propagation. " +
                    "ApplicationId=$($Application.ApplicationId); CertificateThumbprint=$($Application.CertificateThumbprint). $($_.Exception.Message)",
                    $_.Exception
                )
            }
            Wait-SecureM365Propagation -Operation "Teams application access" -Attempt $attempt
        }
    }
}

function Set-SecureM365UserConsent {
    param([Parameter(Mandatory)][hashtable] $RunState)
    $assigned = @(Get-SecureM365UserConsentAssignments)
    $preserved = @($assigned | Where-Object {
        $_ -notmatch '(?i)^managePermissionGrantsForSelf\.' -and $_ -notmatch '(?i)(^|\.)user-default'
    })
    $removed = @($assigned | Where-Object { $_ -notin $preserved })
    if ($removed.Count -gt 0) {
        $RunState.CurrentOperation = "Disable ordinary-user application consent"
        Update-MgPolicyAuthorizationPolicy -BodyParameter @{
            defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = $preserved }
        } -ErrorAction Stop
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Authorization policy"; Action = "Updated"; Id = "authorizationPolicy"; Name = "Ordinary-user consent"
        })
        foreach ($attempt in 1..$PropagationRetryCount) {
            $actual = @(Get-SecureM365UserConsentAssignments)
            if ((ConvertTo-SecureM365ComparableJson $actual) -ceq
                (ConvertTo-SecureM365ComparableJson $preserved)) { break }
            if ($attempt -eq $PropagationRetryCount) {
                throw "Authorization-policy readback did not confirm the expected preserved consent assignments."
            }
            Wait-SecureM365Propagation -Operation "Authorization-policy readback" -Attempt $attempt
        }
    }
    [pscustomobject]@{
        Changed = $removed.Count -gt 0
        RemovedPolicies = $removed
        PreservedPolicies = $preserved
    }
}

function Test-SecureM365DesiredTeamsSettings {
    param([Parameter(Mandatory)] $Policy)
    if (
        [string]::IsNullOrWhiteSpace([string] $Policy.AutoAdmittedUsers) -or
        [string]::IsNullOrWhiteSpace([string] $Policy.DesignatedPresenterRoleMode) -or
        $Policy.AllowAnonymousUsersToJoinMeeting -isnot [bool]
    ) {
        throw "Teams did not return all three required Global meeting-policy properties with the expected types."
    }
    $Policy.AutoAdmittedUsers -eq "InvitedUsers" -and
        $Policy.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride" -and
        $Policy.AllowAnonymousUsersToJoinMeeting -eq $false
}

function Set-SecureM365TeamsControls {
    param([Parameter(Mandatory)][hashtable] $RunState)
    $policy = Get-SecureM365TeamsMeetingPolicy
    $changed = -not (Test-SecureM365DesiredTeamsSettings $policy)
    if ($changed) {
        $RunState.CurrentOperation = "Configure the three Global Teams meeting-policy controls"
        Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers "InvitedUsers" `
            -DesignatedPresenterRoleMode "OrganizerOnlyUserOverride" `
            -AllowAnonymousUsersToJoinMeeting $false -ErrorAction Stop
        [void] $RunState.Changes.Add([pscustomobject]@{
            Resource = "Teams meeting policy"; Action = "Updated"; Id = "Global"; Name = "Lobby, presenters, anonymous join"
        })
        foreach ($attempt in 1..$PropagationRetryCount) {
            $policy = Get-SecureM365TeamsMeetingPolicy
            if (Test-SecureM365DesiredTeamsSettings $policy) { break }
            if ($attempt -eq $PropagationRetryCount) {
                throw "Teams Global policy readback did not confirm all three requested settings."
            }
            Wait-SecureM365Propagation -Operation "Teams Global policy readback" -Attempt $attempt
        }
    }
    [pscustomobject]@{
        Changed = $changed
        Identity = "Global"
        AutoAdmittedUsers = $policy.AutoAdmittedUsers
        DesignatedPresenterRoleMode = $policy.DesignatedPresenterRoleMode
        AllowAnonymousUsersToJoinMeeting = $policy.AllowAnonymousUsersToJoinMeeting
    }
}
#endregion

if (-not $IsWindows) {
    throw "Windows is required for user-scoped DPAPI and the non-exportable CurrentUser certificate."
}
if ($UseGraphDeviceCode -and $UseGraphBrowserPkce) {
    throw "UseGraphDeviceCode and UseGraphBrowserPkce cannot be combined."
}
if ($ReportOnly -and $EmergencyAccessReady) {
    throw "EmergencyAccessReady is an enforcement attestation; do not combine it with ReportOnly."
}
if (@($AccountName | Sort-Object -Unique).Count -ne $AccountName.Count) {
    throw "Supply distinct emergency account names; names are not case-sensitive."
}
foreach ($id in $TemporaryExceptionAccountId) {
    $null = ConvertTo-SecureM365ObjectId $id.Guid "Temporary exception account"
}
$targetTenantId = Resolve-SecureM365TenantId -TenantId $TenantId -PromptIfMissing
$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.Governance"
    "MicrosoftTeams"
)
$missingModules = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
if ($missingModules.Count -gt 0) {
    throw "Install the required modules before configuration: Install-Module -Name $($missingModules -join ',') -Scope CurrentUser -Repository PSGallery"
}
foreach ($moduleName in $requiredModules) {
    Import-Module $moduleName -ErrorAction Stop
}
$additionalScopes = @("Domain.Read.All", "Organization.Read.All")
if ($WhatIfPreference) {
    $additionalScopes += "Application.Read.All"
}
else {
    $additionalScopes += @(
        "Application.ReadWrite.All"
        "AppRoleAssignment.ReadWrite.All"
        "RoleManagement.ReadWrite.Directory"
        "User.Create"
        "Policy.ReadWrite.ConditionalAccess"
        "Policy.ReadWrite.Authorization"
    )
}
$graphParameters = @{
    TenantId = $targetTenantId
    AdditionalScopes = $additionalScopes
    UseDeviceCode = $UseGraphDeviceCode
    UseBrowserPkce = $UseGraphBrowserPkce
}
Connect-SecureM365Graph @graphParameters | Out-Null
$organizations = @(Get-SecureM365GraphCollection `
    -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName")
if ($organizations.Count -ne 1 -or [string] $organizations[0].id -ne $targetTenantId.Guid) {
    throw "Graph organization validation did not return exactly tenant '$($targetTenantId.Guid)'. No configuration was applied."
}
Assert-SecureM365SecurityDefaultsDisabled

$domains = @(Get-SecureM365GraphCollection `
    -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isInitial,isVerified,authenticationType' |
    Where-Object { $_.isInitial -eq $true })
if (
    $domains.Count -ne 1 -or $domains[0].isVerified -ne $true -or
    $domains[0].authenticationType -ne "Managed" -or
    $domains[0].id -notmatch '^[a-z0-9-]+\.onmicrosoft\.com$'
) {
    throw "Expected one initial, verified, managed onmicrosoft.com domain. No configuration was applied."
}
$adminRoleNames = @(
    "Global Administrator"
    "Application Administrator"
    "Authentication Administrator"
    "Authentication Policy Administrator"
    "Billing Administrator"
    "Cloud Application Administrator"
    "Conditional Access Administrator"
    "Exchange Administrator"
    "Helpdesk Administrator"
    "Identity Governance Administrator"
    "Password Administrator"
    "Privileged Authentication Administrator"
    "Privileged Role Administrator"
    "Security Administrator"
    "SharePoint Administrator"
    "User Administrator"
)
$roleDefinitions = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop)
$adminRoleTemplateIds = @(
    foreach ($name in $adminRoleNames) {
        $role = @($roleDefinitions | Where-Object { $_.DisplayName -eq $name -and $_.IsBuiltIn -eq $true })
        if ($role.Count -ne 1) { throw "Could not uniquely resolve the built-in role '$name'." }
        ConvertTo-SecureM365ObjectId $role[0].TemplateId "Role template '$name'"
    }
)
$globalRole = @($roleDefinitions | Where-Object {
    $_.TemplateId -eq "62e90394-69f5-4237-9190-012177145e10" -and $_.IsBuiltIn -eq $true
})
$teamsRole = @($roleDefinitions | Where-Object {
    $_.TemplateId -eq "baf37b3a-610e-45da-9e62-d9d1e5e8914b" -and
    $_.DisplayName -eq "Teams Communications Administrator" -and $_.IsBuiltIn -eq $true
})
if ($globalRole.Count -ne 1 -or $teamsRole.Count -ne 1) {
    throw "Could not uniquely resolve Global Administrator and Teams Communications Administrator."
}
$globalRoleId = ConvertTo-SecureM365ObjectId $globalRole[0].Id "Global Administrator role"
$teamsRoleId = ConvertTo-SecureM365ObjectId $teamsRole[0].Id "Teams Communications Administrator role"
$accountPlan = @(Get-SecureM365EmergencyAccountPlan -Domain $domains[0].id `
    -GlobalAdministratorRoleId $globalRoleId -Names $AccountName)
$newAccounts = @($accountPlan | Where-Object Action -eq "Create")
if ($newAccounts.Count -gt 0 -and $EmergencyAccessReady) {
    throw "EmergencyAccessReady cannot attest to accounts that do not exist yet. Omit it and confirm readiness interactively after provisioning, or use ReportOnly first."
}
$effectivePasswordPath = $null
if ($newAccounts.Count -gt 0) {
    if ([string]::IsNullOrWhiteSpace($PasswordFilePath)) {
        $documents = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
        if ([string]::IsNullOrWhiteSpace($documents)) {
            throw "Could not resolve Documents. Supply PasswordFilePath explicitly."
        }
        $PasswordFilePath = Join-Path (Join-Path $documents "SecureM365") "EmergencyAccessPasswords-$($targetTenantId.Guid).json"
    }
    $effectivePasswordPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PasswordFilePath)
    if (Test-Path -LiteralPath $effectivePasswordPath -PathType Container) {
        throw "PasswordFilePath '$effectivePasswordPath' is a directory."
    }
    if ((Test-Path -LiteralPath $effectivePasswordPath) -and -not $OverwritePasswordFile) {
        throw "Password artifact '$effectivePasswordPath' already exists. Choose a different path, or explicitly approve OverwritePasswordFile after backing it up."
    }
}

$graphPrincipals = @(Get-SecureM365GraphCollection `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'&`$select=id,appId,appRoles")
if ($graphPrincipals.Count -ne 1 -or $graphPrincipals[0].appId -ne "00000003-0000-0000-c000-000000000000") {
    throw "Could not uniquely resolve the Microsoft Graph service principal."
}
$graphPrincipalId = ConvertTo-SecureM365ObjectId $graphPrincipals[0].id "Microsoft Graph service principal"
$organizationRole = @($graphPrincipals[0].appRoles | Where-Object {
    $_.value -eq "Organization.Read.All" -and $_.allowedMemberTypes -contains "Application" -and $_.isEnabled -eq $true
})
if ($organizationRole.Count -ne 1) { throw "Could not uniquely resolve the Organization.Read.All application role." }
$organizationRoleId = ConvertTo-SecureM365ObjectId $organizationRole[0].id "Organization.Read.All application role"
$applicationPlan = Get-SecureM365TeamsApplicationPlan -DisplayName $TeamsApplicationDisplayName `
    -CertificateSubject $TeamsCertificateSubject -GraphServicePrincipalId $graphPrincipalId `
    -OrganizationReadRoleId $organizationRoleId -TeamsRoleDefinitionId $teamsRoleId
if ($applicationPlan.Action -eq "Create" -and -not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw "New-SelfSignedCertificate is unavailable. Run on Windows with the PKI PowerShell module."
}

$knownAccountIds = @($accountPlan | Where-Object { $_.Id } | ForEach-Object { [guid] $_.Id })
$bodyParameters = @{
    AdminRoleTemplateId = $adminRoleTemplateIds
    EmergencyAccessAccountId = $knownAccountIds
    TemporaryExceptionAccountId = $TemporaryExceptionAccountId
}
$bodies = @(Get-SecureM365ConfigurationPolicyBodies @bodyParameters)
$existingPolicies = @(Get-SecureM365GraphCollection `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -Headers @{ Prefer = "include-unknown-enum-members" })
$policyPlans = @(
    foreach ($body in $bodies) {
        $existing = @($existingPolicies | Where-Object { $_.displayName -eq $body.displayName })
        if ($existing.Count -gt 1) {
            throw "Multiple policies are named '$($body.displayName)'. Resolve the ambiguity manually."
        }
        $policyId = $null
        $state = $null
        if ($existing.Count -eq 1) {
            if ($newAccounts.Count -gt 0 -and $body.displayName -ne "CA003 - Block legacy authentication") {
                throw "Policy '$($body.displayName)' already exists, but some requested emergency accounts do not. Its exclusions cannot match the new accounts; review the policy before provisioning."
            }
            $policyId = ConvertTo-SecureM365ObjectId $existing[0].id "Policy '$($body.displayName)'"
            $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $policyId
            Assert-SecureM365PolicyMatch -Policy $policy -Body $body
            $state = [string] $policy.state
        }
        [pscustomobject]@{
            DisplayName = $body.displayName
            Id = $policyId
            State = $state
            Action = if (-not $policyId) { "Create report-only" }
                elseif ($state -eq "enabled" -or $ReportOnly) { "Reuse" }
                else { "Enable after review" }
            TargetState = if ($ReportOnly -and $state -ne "enabled") {
                "enabledForReportingButNotEnforced"
            }
            else { "enabled" }
        }
    }
)
$null = @(Get-SecureM365UserConsentAssignments)
$configurationPlan = [pscustomobject]@{
    Status = "Planned"
    TenantId = $targetTenantId.Guid
    TenantDisplayName = [string] $organizations[0].displayName
    EmergencyAccounts = @($accountPlan | Select-Object UserPrincipalName, Id, RoleAssignmentId, Action)
    PasswordFilePath = $effectivePasswordPath
    TeamsApplication = $applicationPlan
    ConditionalAccessPolicies = $policyPlans
    UserApplicationConsent = "Remove ordinary-user self-consent assignments; preserve other assignments"
    TeamsGlobalPolicy = [pscustomobject]@{
        AutoAdmittedUsers = "InvitedUsers"
        DesignatedPresenterRoleMode = "OrganizerOnlyUserOverride"
        AllowAnonymousUsersToJoinMeeting = $false
    }
    SecurityDefaultsChanged = $false
}
Write-Host "`nMicrosoft 365 configuration plan: $($configurationPlan.TenantDisplayName) ($($targetTenantId.Guid))"
$configurationPlan.EmergencyAccounts | Format-Table UserPrincipalName, Action, Id -AutoSize | Out-Host
Write-Host "Teams application: $($applicationPlan.Action) '$TeamsApplicationDisplayName'; certificate '$TeamsCertificateSubject'."
$policyPlans | Format-Table DisplayName, Action, TargetState -Wrap | Out-Host
Write-Host "Also disable ordinary-user application consent and configure the three Global Teams meeting settings."
Write-Warning "CA005 preserves script 18's passwordChange plus MFA-strength grant, including its documented compatibility caveat. No alternative grant will be silently substituted."
if (-not $PSCmdlet.ShouldProcess(
    $targetTenantId.Guid,
    "Apply the displayed emergency-account, Teams application, CA001-CA005, consent, and Global Teams configuration"
)) {
    if ($PassThru) { $configurationPlan }
    return
}

$ConfirmPreference = "None"
$runState = @{
    CurrentOperation = "Start approved configuration"
    Changes = [Collections.Generic.List[object]]::new()
}
try {
    $accounts = @(New-SecureM365EmergencyAccounts -TenantId $targetTenantId -Plans $accountPlan `
        -RoleDefinitionId $globalRoleId -Path $effectivePasswordPath -Overwrite:$OverwritePasswordFile -RunState $runState)
    $accountIds = @($accounts | ForEach-Object {
        [guid] (ConvertTo-SecureM365ObjectId $_.Id "Provisioned emergency account '$($_.UserPrincipalName)'")
    })
    if ($accountIds.Count -ne $AccountName.Count -or @($accountIds | Sort-Object -Unique).Count -ne $AccountName.Count) {
        throw "The complete set of distinct emergency-account IDs was not verified. No Conditional Access policy will be created or enabled."
    }
    $runState.CurrentOperation = "Create or reuse the dedicated Teams application"
    $application = New-SecureM365TeamsApplication -Plan $applicationPlan -RunState $runState
    $runState.CurrentOperation = "Validate certificate-authenticated Teams meeting-policy access"
    Connect-SecureM365ConfiguredTeams -TenantId $targetTenantId -Application $application | Out-Null

    $bodyParameters.EmergencyAccessAccountId = $accountIds
    $bodies = @(Get-SecureM365ConfigurationPolicyBodies @bodyParameters)
    foreach ($index in 0..($bodies.Count - 1)) {
        $body = $bodies[$index]
        $plan = $policyPlans[$index]
        $runState.CurrentOperation = "Stage or verify '$($body.displayName)'"
        if (-not $plan.Id) {
            $created = New-SecureM365ConditionalAccessPolicy -BodyParameter $body
            $plan.Id = ConvertTo-SecureM365ObjectId $created.Id "New policy '$($body.displayName)'"
            [void] $runState.Changes.Add([pscustomobject]@{
                Resource = "Conditional Access"; Action = "Created report-only"; Id = $plan.Id; Name = $body.displayName
            })
            $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $plan.Id -ExpectedState "enabledForReportingButNotEnforced"
        }
        else {
            $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $plan.Id
        }
        Assert-SecureM365PolicyMatch -Policy $policy -Body $body
        $plan.State = [string] $policy.state
    }

    $consent = Set-SecureM365UserConsent -RunState $runState
    $teams = Set-SecureM365TeamsControls -RunState $runState
    $toEnable = @($policyPlans | Where-Object State -eq "enabledForReportingButNotEnforced")
    if (-not $ReportOnly -and $toEnable.Count -gt 0) {
        $runState.CurrentOperation = "Confirm emergency access and review policy enforcement"
        Write-Warning "Before enabling policies, enroll and test phishing-resistant MFA for every emergency account. Also confirm administrator/user MFA, modern-client readiness, SSPR/password writeback where applicable, and the impact of all five policies."
        $readyForAll = $false
        $notReadyForAll = $false
        if (-not $EmergencyAccessReady -and -not $PSCmdlet.ShouldContinue(
            "Have you tested emergency access for $($accounts.UserPrincipalName -join ', '), confirmed the affected users' readiness, and reviewed CA001-CA005? Answer No to leave staged policies unenforced.",
            "Enable reviewed Conditional Access policies",
            $true,
            [ref] $readyForAll,
            [ref] $notReadyForAll
        )) {
            throw "Readiness was not confirmed. Newly created policies remain report-only; other completed configuration is retained. Review it and rerun this same script when ready."
        }
        Connect-SecureM365Graph @graphParameters | Out-Null
        Assert-SecureM365SecurityDefaultsDisabled
        $verifiedAccounts = @(Get-SecureM365EmergencyAccountPlan -Domain $domains[0].id `
            -GlobalAdministratorRoleId $globalRoleId -Names $AccountName)
        if (@($verifiedAccounts | Where-Object Action -ne "Reuse").Count -gt 0 -or
            (ConvertTo-SecureM365ComparableJson @($verifiedAccounts.Id)) -cne
            (ConvertTo-SecureM365ComparableJson @($accounts.Id))) {
            throw "The emergency accounts changed after preflight. No remaining policy will be enabled."
        }
        foreach ($index in 0..($bodies.Count - 1)) {
            $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $policyPlans[$index].Id
            Assert-SecureM365PolicyMatch -Policy $policy -Body $bodies[$index]
        }
        foreach ($index in 0..($bodies.Count - 1)) {
            $plan = $policyPlans[$index]
            $runState.CurrentOperation = "Enable reviewed policy '$($plan.DisplayName)' ($($plan.Id))"
            $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $plan.Id
            Assert-SecureM365PolicyMatch -Policy $policy -Body $bodies[$index]
            if ($policy.state -eq "enabledForReportingButNotEnforced") {
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $plan.Id `
                    -BodyParameter @{ state = "enabled" } -ErrorAction Stop
                [void] $runState.Changes.Add([pscustomobject]@{
                    Resource = "Conditional Access"; Action = "Enabled"; Id = $plan.Id; Name = $plan.DisplayName
                })
            }
            $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $plan.Id -ExpectedState "enabled"
            Assert-SecureM365PolicyMatch -Policy $policy -Body $bodies[$index]
            $plan.State = [string] $policy.state
        }
    }

    $runState.CurrentOperation = "Verify final Conditional Access, consent, and Teams configuration"
    foreach ($index in 0..($bodies.Count - 1)) {
        $plan = $policyPlans[$index]
        $policy = Get-ReviewedConditionalAccessPolicy -PolicyId $plan.Id -ExpectedState $plan.TargetState
        Assert-SecureM365PolicyMatch -Policy $policy -Body $bodies[$index]
        $plan.State = [string] $policy.state
    }
    if ((ConvertTo-SecureM365ComparableJson @(Get-SecureM365UserConsentAssignments)) -cne
        (ConvertTo-SecureM365ComparableJson $consent.PreservedPolicies)) {
        throw "The authorization-policy assignments changed after configuration. Review ordinary-user consent before retrying."
    }
    if (-not (Test-SecureM365DesiredTeamsSettings (Get-SecureM365TeamsMeetingPolicy))) {
        throw "The Global Teams meeting settings changed after configuration."
    }

    $result = [pscustomobject]@{
        Status = if ($ReportOnly) { "ReportOnlyRun" } else { "Configured" }
        TenantId = $targetTenantId.Guid
        CheckedAt = [datetimeoffset]::UtcNow
        Changed = $runState.Changes.Count -gt 0
        EmergencyAccounts = @($accounts | Select-Object Id, UserPrincipalName, RoleAssignmentId, Action)
        PasswordFilePath = $effectivePasswordPath
        TeamsApplication = $application
        ConditionalAccessPolicies = @($policyPlans | Select-Object Id, DisplayName, State)
        UserApplicationConsent = $consent
        TeamsGlobalPolicy = $teams
        SecurityDefaultsChanged = $false
        Changes = $runState.Changes.ToArray()
    }
    $result.ConditionalAccessPolicies | Format-Table DisplayName, State -Wrap | Out-Host
    Write-Host "Configuration completed: $($result.Status). Tenant: $($targetTenantId.Guid)."
    Write-Host "Teams application ID: $($application.ApplicationId); certificate: $($application.CertificateThumbprint)."
    Write-Host "Consent and all three Global Teams settings were read back. SSPR scope, enrollment, and monitoring are not configured by this script."
    if ($PassThru) { $result }
}
catch {
    Write-Warning "Configuration stopped during: $($runState.CurrentOperation). Completed changes were not rolled back."
    foreach ($change in $runState.Changes) {
        Write-Warning "Confirmed $($change.Resource): $($change.Action); name='$($change.Name)'; ID='$($change.Id)'."
    }
    Write-Warning "Review the requested accounts, application/certificate, and named policies before retrying, including writes whose outcome is unknown. Matching completed objects can be reused; differences and partial identities require manual review."
    throw
}
