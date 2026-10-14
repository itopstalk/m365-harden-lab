#Requires -Version 5.1

<#
.SYNOPSIS
Installs the lab tools, validates tenant connections, and assesses Microsoft 365.

.DESCRIPTION
Standalone combination of scripts 00, 01, and 99. All required helpers from
SecureM365.Common.psm1 are embedded; no other repository file is required.
Installs missing PowerShell modules for the current user from PSGallery, validates
Microsoft Graph and Teams access to the intended tenant, and reports the same ten
recommendations as script 99. Tenant configuration is read-only.

The assessment requires PowerShell 7.2 or later. When started in Windows
PowerShell or an older PowerShell version, installs PowerShell 7 using WinGet,
then stops. Open pwsh.exe and rerun this file to continue.

As in script 00, the module inventory includes Microsoft.Graph.Authentication,
Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.Governance,
MicrosoftTeams, and ExchangeOnlineManagement. Only Graph Authentication and
Teams are imported for this assessment; no Exchange connection is needed.

As in script 01, the default Graph consent profile includes the write permissions
used by the other lab scripts. Use -ConsentForAllScripts:$false for read-only
assessment consent. Graph consent does not grant Entra roles or Teams permissions.
Teams meeting-policy access is always validated; no -IncludeTeams switch is needed.
Teams failures are recorded as UNKNOWN for the three Teams recommendations rather
than preventing the remaining checks or snapshot.

Every assessment writes a timestamped JSON snapshot under C:\SecureM365Snapshots
by default. IMPLEMENTED means that script 99's recognition rule was satisfied,
not that every account or sign-in is protected. MFA and risk-policy coverage and
registration readiness are separate advisories. Report-only and disabled policies
do not count as enabled protection. Teams checks assess only the Global policy.

After displaying the final assessment heading, results table, summary, and
snapshot path, saves the same text as UTF-8 to hardening-results.txt in the current
working directory. Replaces the previous file, including a report from script ZZ.
Module inventories, connection messages, and warning-stream output are not included.

SSPR All-scope confirmation defaults to true, preserving script 99's lab behavior.
Microsoft Graph does not expose the exact Password reset > Properties scope.
Use -SsprAllScopeConfirmed:$false unless All has been independently verified.
Registration data is advisory and can lag changes by up to 36 hours.

.PARAMETER TenantId
Microsoft Entra tenant GUID in the worldwide cloud. Prompts when omitted and
rejects blank, invalid, and all-zero values. Existing Graph connections are reused
only after validating the tenant, delegated user, and required scopes.

.PARAMETER ConsentForAllScripts
Defaults to true, requesting the complete delegated Graph scope set used by
scripts 00-99, including write permissions. Set to false for assessment-only
read scopes. This does not modify tenant settings or assign administrator roles.

.PARAMETER UseGraphDeviceCode
Use device-code authentication for Graph. Cannot be combined with browser PKCE.

.PARAMETER UseGraphBrowserPkce
Use system-browser authorization-code authentication with PKCE and a temporary
localhost callback. Intended for managed terminals where WAM or device prompts
are not visible. Passwords and tokens are never saved.

.PARAMETER UseTeamsDeviceAuthentication
Use device authentication for Teams instead of the normal interactive connection.
Cannot be combined with certificate-based Teams authentication.

.PARAMETER TeamsApplicationId
Use a dedicated Teams application with exactly one certificate parameter.

.PARAMETER TeamsCertificateThumbprint
Thumbprint in Cert:\CurrentUser\My for the Teams application certificate.

.PARAMETER TeamsCertificatePath
Path to a PFX outside the script directory and its Git repository, if present.
Use only when the private key was deliberately deployed to this machine/profile.

.PARAMETER TeamsCertificatePassword
Secure-string password for TeamsCertificatePath. Not used with a thumbprint.

.PARAMETER ApprovedExcludedUserId
Approved Conditional Access user exclusions, including emergency-account object
IDs. Affects the MFA/risk coverage advisories and legacy-authentication assessment,
not the registration advisory population.

.PARAMETER ApprovedExcludedGroupId
Approved Conditional Access group object IDs.

.PARAMETER ApprovedExcludedRoleId
Approved Conditional Access role template IDs.

.PARAMETER SnapshotDirectory
Directory for timestamped JSON snapshots. Defaults to C:\SecureM365Snapshots
and is created when necessary. Existing snapshots are never overwritten.

.PARAMETER SsprAllScopeConfirmed
Defaults to true as in script 99. Set to false whenever Password reset >
Properties = All has not been independently confirmed.

.PARAMETER PassThru
Return only the ten structured assessment objects, suitable for filtering or
export. Tool inventories and connection summaries are displayed on the host,
not mixed into these results.

.NOTES
-WhatIf previews tool installation only: no authentication, tenant reads, or
text report or snapshot writes occur. Declined or failed required installations
stop assessment.
The embedded authentication, policy evaluation, and report logic are derived
from scripts 00, 01, 99, and SecureM365.Common.psm1 in this repository.

.EXAMPLE
.\AA-AssessM365Status.ps1 -UseGraphBrowserPkce -ConsentForAllScripts:$false

.EXAMPLE
$results = .\AA-AssessM365Status.ps1 -TenantId $TenantId -PassThru

.EXAMPLE
.\AA-AssessM365Status.ps1 -TenantId $TenantId -ConsentForAllScripts:$false -SsprAllScopeConfirmed:$false

.EXAMPLE
.\AA-AssessM365Status.ps1 -WhatIf

.LINK
https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph

.LINK
https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $TenantId,
    [Alias("ConsentAll")]
    [switch] $ConsentForAllScripts = $true,
    [Alias("UseDeviceCode")]
    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce,
    [switch] $UseTeamsDeviceAuthentication,
    [guid] $TeamsApplicationId,
    [string] $TeamsCertificateThumbprint,
    [string] $TeamsCertificatePath,
    [securestring] $TeamsCertificatePassword,
    [guid[]] $ApprovedExcludedUserId = @(),
    [guid[]] $ApprovedExcludedGroupId = @(),
    [guid[]] $ApprovedExcludedRoleId = @(),
    [string] $SnapshotDirectory = "C:\SecureM365Snapshots",
    [switch] $SsprAllScopeConfirmed = $true,
    [switch] $PassThru
)

$ErrorActionPreference = "Stop"

#region Embedded shared helpers
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

function Connect-SecureM365Teams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $TenantId,

        [switch] $UseDeviceAuthentication,
        [switch] $ValidateMeetingPolicyAccess,

        [Nullable[guid]] $ApplicationId,
        [string] $CertificateThumbprint,
        [string] $CertificatePath,
        [securestring] $CertificatePassword
    )

    $applicationAuthenticationRequested =
        ($null -ne $ApplicationId -and $ApplicationId -ne [guid]::Empty) -or
        -not [string]::IsNullOrWhiteSpace($CertificateThumbprint) -or
        -not [string]::IsNullOrWhiteSpace($CertificatePath) -or
        $null -ne $CertificatePassword
    if ($applicationAuthenticationRequested) {
        if ($null -eq $ApplicationId -or $ApplicationId -eq [guid]::Empty) {
            throw "ApplicationId is required when certificate-based Teams authentication is requested."
        }
        if ($UseDeviceAuthentication) {
            throw "UseDeviceAuthentication cannot be combined with certificate-based Teams authentication."
        }
        if (
            [string]::IsNullOrWhiteSpace($CertificateThumbprint) -eq
            [string]::IsNullOrWhiteSpace($CertificatePath)
        ) {
            throw "Specify exactly one of CertificateThumbprint or CertificatePath for certificate-based Teams authentication."
        }
        if ($null -ne $CertificatePassword -and [string]::IsNullOrWhiteSpace($CertificatePath)) {
            throw "CertificatePassword can be used only with CertificatePath."
        }
    }

    $connectParameters = @{
        TenantId    = $TenantId.Guid
        ErrorAction = "Stop"
    }
    $certificate = $null
    if ($applicationAuthenticationRequested) {
        $connectParameters.ApplicationId = $ApplicationId.Guid
        if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            $normalizedThumbprint = $CertificateThumbprint -replace '\s', ''
            if ($normalizedThumbprint -notmatch '^[0-9A-Fa-f]{40,128}$') {
                throw "CertificateThumbprint must contain only hexadecimal characters."
            }
            $connectParameters.CertificateThumbprint = $normalizedThumbprint
        }
        else {
            $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CertificatePath)
            if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
                throw "CertificatePath '$CertificatePath' does not exist."
            }
            $protectedDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
            $directory = [IO.DirectoryInfo]::new($protectedDirectory)
            while ($null -ne $directory) {
                if (Test-Path -LiteralPath (Join-Path $directory.FullName ".git")) {
                    $protectedDirectory = $directory.FullName
                    break
                }
                $directory = $directory.Parent
            }
            $fullCertificatePath = [IO.Path]::GetFullPath($resolvedPath)
            if ($fullCertificatePath.StartsWith(
                $protectedDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "CertificatePath must be outside the script directory and its Git repository because a PFX contains private key material."
            }
            $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
            $certificate = if ($null -eq $CertificatePassword) {
                [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    $fullCertificatePath, [string]::Empty, $flags
                )
            }
            else {
                [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    $fullCertificatePath, $CertificatePassword, $flags
                )
            }
            if (-not $certificate.HasPrivateKey) {
                $certificate.Dispose()
                throw "CertificatePath '$CertificatePath' does not contain an accessible private key."
            }
            $connectParameters.Certificate = $certificate
        }
    }
    elseif ($UseDeviceAuthentication) {
        $connectParameters.UseDeviceAuthentication = $true
    }

    try {
        $connection = Connect-MicrosoftTeams @connectParameters
    }
    catch {
        if ($null -ne $certificate) {
            $certificate.Dispose()
        }
        throw
    }
    if ([string] $connection.TenantId -ne $TenantId.Guid) {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        throw "Microsoft Teams connected to tenant '$($connection.TenantId)' instead of '$($TenantId.Guid)'."
    }

    if ($ValidateMeetingPolicyAccess) {
        try {
            $null = Get-SecureM365TeamsMeetingPolicy
        }
        catch {
            $details = $_.Exception.Message
            if (-not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
                $details += " $($_.ErrorDetails.Message)"
            }
            throw [System.InvalidOperationException]::new(
                "Microsoft Teams connected to tenant '$($TenantId.Guid)', but reading the Global meeting policy failed. " +
                "For Forbidden/Access Denied, verify the Teams identity has an active role permitted to read meeting policies " +
                "(for example, Teams Communications Administrator). For application authentication, assign the role directly to " +
                "the service principal and grant only Microsoft Graph Organization.Read.All. Activate PIM for delegated use if needed and allow changes to propagate, " +
                "then run Disconnect-MicrosoftTeams and rerun AA-AssessM365Status.ps1. Graph consent does not grant Teams permissions. " +
                "Original error: $details",
                $_.Exception
            )
        }
    }

    $connection
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

function Test-SecureM365CaTargetsAllUsers {
    param([Parameter(Mandatory)] $Policy)
    @($Policy.conditions.users.includeUsers) -contains "All"
}

function Test-SecureM365CaHasOnlyApprovedExclusions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Policy,

        [string[]] $ApprovedExcludedUserIds = @(),
        [string[]] $ApprovedExcludedGroupIds = @(),
        [string[]] $ApprovedExcludedRoleIds = @(),
        [switch] $AllowGuestOrExternalUserExclusion
    )

    $users = $Policy.conditions.users
    $unexpectedUsers = @(
        @($users.excludeUsers) |
        Where-Object { $_ -and $_ -notin $ApprovedExcludedUserIds }
    )
    $unexpectedGroups = @(
        @($users.excludeGroups) |
        Where-Object { $_ -and $_ -notin $ApprovedExcludedGroupIds }
    )
    $unexpectedRoles = @(
        @($users.excludeRoles) |
        Where-Object { $_ -and $_ -notin $ApprovedExcludedRoleIds }
    )
    $hasGuestExclusion =
        $null -ne $users.excludeGuestsOrExternalUsers -and
        -not $AllowGuestOrExternalUserExclusion

    ($unexpectedUsers.Count -eq 0) -and
    ($unexpectedGroups.Count -eq 0) -and
    ($unexpectedRoles.Count -eq 0) -and
    (-not $hasGuestExclusion)
}

function Test-SecureM365CaTargetsAllResources {
    param([Parameter(Mandatory)] $Policy)

    (@($Policy.conditions.applications.includeApplications) -contains "All") -and
    (@($Policy.conditions.applications.excludeApplications | Where-Object { $_ }).Count -eq 0)
}

function Test-SecureM365CaRequiresMfa {
    param([Parameter(Mandatory)] $Policy)

    $grant = $Policy.grantControls
    $controls = @($grant.builtInControls | Where-Object { $_ })
    $strength = $grant.authenticationStrength
    $hasMfaStrength =
        $strength.requirementsSatisfied -eq "mfa" -or
        $strength.id -in @(
            "00000000-0000-0000-0000-000000000002"
            "00000000-0000-0000-0000-000000000003"
            "00000000-0000-0000-0000-000000000004"
        )
    if (
        $controls -contains "block" -or
        (-not $hasMfaStrength -and $controls -notcontains "mfa")
    ) {
        return $false
    }
    if ($grant.operator -eq "AND") {
        return $true
    }
    if ($grant.operator -ne "OR") {
        return $false
    }

    # An OR alternative such as a compliant device lets the user bypass MFA.
    $alternatives = @($controls | Where-Object { $_ -ne "mfa" })
    $alternatives.Count -eq 0 -and
        @($grant.termsOfUse | Where-Object { $_ }).Count -eq 0 -and
        @($grant.customAuthenticationFactors | Where-Object { $_ }).Count -eq 0 -and
        ($null -eq $strength -or $hasMfaStrength)
}

function Test-SecureM365CaPolicyScope {
    param(
        [Parameter(Mandatory)] $Policy,
        [hashtable] $ApprovedExclusions = @{},
        [ValidateSet("None", "SignIn", "User")] [string] $Risk = "None",
        [switch] $Legacy
    )

    if (
        $Policy.state -ne "enabled" -or
        -not (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $Policy @ApprovedExclusions) -or
        -not (Test-SecureM365CaTargetsAllResources $Policy)
    ) {
        return $false
    }

    $conditions = $Policy.conditions
    $apps = $conditions.applications
    if (
        $null -ne $apps.applicationFilter -or
        @($apps.includeUserActions | Where-Object { $_ }).Count -gt 0 -or
        @($apps.includeAuthenticationContextClassReferences | Where-Object { $_ }).Count -gt 0
    ) {
        return $false
    }

    $clients = @($conditions.clientAppTypes)
    if ($clients -notcontains "all") {
        if (
            -not $Legacy -or
            $clients -notcontains "exchangeActiveSync" -or
            $clients -notcontains "other"
        ) {
            return $false
        }
    }

    $allowedConditions = @("users", "applications", "clientAppTypes", "@odata.type")
    if ($Risk -eq "SignIn") { $allowedConditions += "signInRiskLevels" }
    if ($Risk -eq "User") { $allowedConditions += "userRiskLevels" }
    $conditionNames = if ($conditions -is [System.Collections.IDictionary]) {
        @($conditions.Keys)
    }
    else {
        @($conditions.PSObject.Properties.Name)
    }
    foreach ($name in $conditionNames) {
        if ($name -in $allowedConditions) { continue }
        $value = $conditions.$name
        if ($null -eq $value -or @($value).Count -eq 0) { continue }
        if (
            $name -eq "platforms" -and
            @($value.includePlatforms) -contains "all" -and
            @($value.excludePlatforms | Where-Object { $_ }).Count -eq 0
        ) { continue }
        if (
            $name -eq "locations" -and
            @($value.includeLocations) -contains "All" -and
            @($value.excludeLocations | Where-Object { $_ }).Count -eq 0
        ) { continue }
        return $false
    }
    $true
}

function Get-SecureM365MfaPolicyAssessment {
    [CmdletBinding(DefaultParameterSetName = "Mfa")]
    param(
        [AllowEmptyCollection()]
        [object[]] $Policies = @(),
        [Parameter(ParameterSetName = "Mfa")]
        [bool] $SecurityDefaultsEnabled,
        [Parameter(ParameterSetName = "Mfa")]
        [switch] $Administrators,
        [Parameter(ParameterSetName = "Mfa")]
        [string[]] $RequiredRoleIds = @(),
        [hashtable] $ApprovedExclusions = @{},
        [Parameter(ParameterSetName = "Mfa")]
        [string] $CoverageReadError,
        [Parameter(Mandatory, ParameterSetName = "SignInRisk")]
        [switch] $SignInRisk,
        [Parameter(Mandatory, ParameterSetName = "UserRisk")]
        [switch] $UserRisk
    )

    $isRiskPolicy = $SignInRisk -or $UserRisk
    $policyKind = if ($UserRisk) { "user risk remediation" } elseif ($SignInRisk) { "sign-in risk MFA" } else { "MFA" }
    $scopeRisk = if ($UserRisk) { "User" } elseif ($SignInRisk) { "SignIn" } else { "None" }
    $securityDefaultsAccepted = -not $isRiskPolicy -and $SecurityDefaultsEnabled
    $matching = @(
        $Policies | Where-Object {
            $policy = $_
            $remediations = @($policy.grantControls.builtInControls | Where-Object {
                $_ -in @("passwordChange", "riskRemediation")
            })
            (Test-SecureM365CaRequiresMfa $policy) -and
            (
                (Test-SecureM365CaTargetsAllUsers $policy) -or
                ($Administrators -and @($policy.conditions.users.includeRoles | Where-Object { $_ }).Count -gt 0)
            ) -and
            (
                -not $isRiskPolicy -or
                (
                    $policy.sessionControls.signInFrequency.isEnabled -is [bool] -and
                    (Test-SecureM365CaUsesEveryTimeSignInFrequency $policy) -and
                    $policy.sessionControls.signInFrequency.authenticationType -eq "primaryAndSecondaryAuthentication"
                )
            ) -and
            (
                -not $SignInRisk -or
                (
                    @($policy.conditions.signInRiskLevels) -contains "medium" -and
                    @($policy.conditions.signInRiskLevels) -contains "high"
                )
            ) -and
            (
                -not $UserRisk -or
                (
                    @($policy.conditions.userRiskLevels) -contains "high" -and
                    $policy.grantControls.operator -eq "AND" -and
                    $remediations.Count -eq 1 -and
                    (
                        $remediations -notcontains "riskRemediation" -or
                        (
                            # Authentication strength cannot be combined with the built-in MFA grant.
                            $null -ne $policy.grantControls.authenticationStrength -and
                            @($policy.grantControls.builtInControls) -notcontains "mfa"
                        )
                    )
                )
            )
        }
    )
    foreach ($policy in $matching) {
        if (
            [string]::IsNullOrWhiteSpace([string] $policy.id) -or
            [string]::IsNullOrWhiteSpace([string] $policy.displayName) -or
            $policy.state -notin @("enabled", "disabled", "enabledForReportingButNotEnforced")
        ) {
            throw "A matching $policyKind policy has missing identity data or an unrecognized state. Its configuration cannot be verified."
        }
    }
    $enabled = @($matching | Where-Object state -eq "enabled")
    $configured = $securityDefaultsAccepted -or $enabled.Count -gt 0
    $audience = if ($Administrators) { "all users or directory roles" } else { "all users" }
    $policyEvidence = if ($securityDefaultsAccepted) {
        "Security defaults is enabled."
    }
    elseif ($enabled.Count -gt 0) {
        "Enabled $policyKind policy found: " + (($enabled | ForEach-Object {
            "'$($_.displayName)' (ID: $($_.id), state: $($_.state))"
        }) -join "; ") + "."
    }
    elseif ($matching.Count -gt 0) {
        "$policyKind policy found, but not enabled: " + (($matching | ForEach-Object {
            "'$($_.displayName)' (ID: $($_.id), state: $($_.state))"
        }) -join "; ") + ". Disabled and report-only policies do not enforce MFA."
    }
    elseif ($isRiskPolicy) {
        "No matching $policyKind policy directly targets all users. A policy name or optional grant is not sufficient."
    }
    else {
        "No matching MFA policy directly targets $audience, and security defaults is disabled. A policy name or MFA OR a non-MFA grant is not sufficient."
    }
    if ($SignInRisk) {
        $policyEvidence += " Matching requires All users, medium and high sign-in risk, MFA, and every-time primary-and-secondary reauthentication. Security Defaults alone does not satisfy this check."
    }
    elseif ($UserRisk) {
        $policyEvidence += " Matching requires All users, high user risk, MFA AND exactly one remediation control (passwordChange or riskRemediation), and every-time primary-and-secondary reauthentication. Modern riskRemediation requires an MFA authentication strength. Security Defaults alone does not satisfy this check."
    }

    $broadPolicies = @($enabled | Where-Object {
        Test-SecureM365CaPolicyScope -Policy $_ -ApprovedExclusions $ApprovedExclusions -Risk $scopeRisk
    })
    $allUsersCovered = @($broadPolicies | Where-Object {
        Test-SecureM365CaTargetsAllUsers $_
    }).Count -gt 0
    $coveredRoles = @(
        foreach ($policy in $broadPolicies) {
            @($policy.conditions.users.includeRoles) |
                Where-Object { $_ -and $_ -notin @($policy.conditions.users.excludeRoles) }
        }
    )
    $missingRoles = @($RequiredRoleIds | Where-Object { $_ -notin $coveredRoles })
    $coverageVerified = if ($securityDefaultsAccepted -or $allUsersCovered) {
        $missingRoles = @()
        $true
    }
    elseif ($Administrators -and ($RequiredRoleIds.Count -eq 0 -or $CoverageReadError)) {
        $null
    }
    else {
        $Administrators -and $missingRoles.Count -eq 0
    }
    $coverageEvidence = if ($coverageVerified -eq $true) {
        "Coverage advisory: broad $policyKind protection with only approved exclusions was verified."
    }
    elseif ($null -eq $coverageVerified) {
        "Coverage advisory: administrator role coverage could not be evaluated. $CoverageReadError".Trim()
    }
    else {
        "Coverage advisory: broad protection was NOT verified. Review role coverage, resource/client/risk conditions, and unapproved exclusions."
    }

    $policySummaries = @(
        foreach ($policy in $matching) {
            $summary = [ordered]@{
                Id = [string] $policy.id
                DisplayName = [string] $policy.displayName
                State = [string] $policy.state
                TargetsAllUsers = Test-SecureM365CaTargetsAllUsers $policy
                IncludedRoleIds = @($policy.conditions.users.includeRoles | Where-Object { $_ })
                ExcludedUserIds = @($policy.conditions.users.excludeUsers | Where-Object { $_ })
                ExcludedGroupIds = @($policy.conditions.users.excludeGroups | Where-Object { $_ })
                ExcludedRoleIds = @($policy.conditions.users.excludeRoles | Where-Object { $_ })
                ExcludesGuestsOrExternalUsers = $null -ne $policy.conditions.users.excludeGuestsOrExternalUsers
                ExclusionsApproved = Test-SecureM365CaHasOnlyApprovedExclusions -Policy $policy @ApprovedExclusions
            }
            if ($SignInRisk) {
                $summary.SignInRiskLevels = @($policy.conditions.signInRiskLevels)
            }
            if ($UserRisk) {
                $summary.UserRiskLevels = @($policy.conditions.userRiskLevels)
                $summary.RemediationControl = @($policy.grantControls.builtInControls | Where-Object {
                    $_ -in @("passwordChange", "riskRemediation")
                })[0]
                $summary.GrantOperator = $policy.grantControls.operator
                $summary.AuthenticationStrengthId = $policy.grantControls.authenticationStrength.id
            }
            if ($isRiskPolicy) {
                $summary.SignInFrequency = [pscustomobject]@{
                    IsEnabled = $policy.sessionControls.signInFrequency.isEnabled
                    FrequencyInterval = $policy.sessionControls.signInFrequency.frequencyInterval
                    AuthenticationType = $policy.sessionControls.signInFrequency.authenticationType
                }
            }
            [pscustomobject] $summary
        }
    )
    $exclusions = @(
        foreach ($policy in $policySummaries | Where-Object State -eq "enabled") {
            if (
                $policy.ExcludedUserIds.Count -gt 0 -or
                $policy.ExcludedGroupIds.Count -gt 0 -or
                $policy.ExcludedRoleIds.Count -gt 0 -or
                $policy.ExcludesGuestsOrExternalUsers
            ) {
                "'$($policy.DisplayName)': excluded users=[$($policy.ExcludedUserIds -join ', ')]; " +
                "groups=[$($policy.ExcludedGroupIds -join ', ')]; roles=[$($policy.ExcludedRoleIds -join ', ')]; " +
                "guests/external=$($policy.ExcludesGuestsOrExternalUsers); approved=$($policy.ExclusionsApproved)"
            }
        }
    )
    $exclusionEvidence = if ($exclusions.Count -gt 0) {
        "Exclusion advisory: $($exclusions -join '; '). Exclusions do not change the enabled-policy result."
    }
    else {
        "Exclusion advisory: no exclusions found on matching enabled Conditional Access policies."
    }

    [pscustomobject]@{
        Status = if ($configured) { "IMPLEMENTED" } else { "NOT-CONFIGURED" }
        AssessmentBasis = "Enabled $policyKind configuration, not complete sign-in coverage"
        PolicyFound = $matching.Count -gt 0
        EnabledPolicyFound = $enabled.Count -gt 0
        SecurityDefaultsEnabled = if ($isRiskPolicy) { $null } else { $SecurityDefaultsEnabled }
        ProtectionConfigured = $configured
        Resolved = $configured
        CoverageVerified = $coverageVerified
        MissingAdministrativeRoles = $missingRoles
        Policies = $policySummaries
        CoverageEvidence = $coverageEvidence
        ExclusionEvidence = $exclusionEvidence
        Evidence = "$policyEvidence This checks configuration, not every account or sign-in. $coverageEvidence $exclusionEvidence"
    }
}

function Test-SecureM365CaUsesEveryTimeSignInFrequency {
    param([Parameter(Mandatory)] $Policy)

    $frequency = $Policy.sessionControls.signInFrequency
    ($null -ne $frequency) -and
    ($frequency.isEnabled -eq $true) -and
    ($frequency.frequencyInterval -eq "everyTime")
}
#endregion

#region Recommendation report helpers
function New-Assessment {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("IMPLEMENTED", "NOT-CONFIGURED", "UNKNOWN")]
        [string] $Status,

        [Parameter(Mandatory)]
        [string] $Details,

        [psobject] $PolicyConfiguration
    )
    [pscustomobject]@{
        Status   = $Status
        Evidence = $Details
        # Retained for consumers of earlier script versions.
        Details  = $Details
        PolicyConfiguration = $PolicyConfiguration
    }
}

function Save-RecommendationSnapshot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object[]] $Results,

        [Parameter(Mandatory)]
        [guid] $TenantId,

        [Parameter(Mandatory)]
        [datetimeoffset] $CheckedAt,

        [Parameter(Mandatory)]
        [string] $Directory
    )

    if ([string]::IsNullOrWhiteSpace($Directory)) {
        throw "SnapshotDirectory cannot be empty."
    }
    if (Test-Path -LiteralPath $Directory) {
        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
            throw "SnapshotDirectory '$Directory' exists but is not a directory."
        }
    }
    else {
        $null = New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop
    }

    $resolvedDirectory = (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path
    $timestamp = $CheckedAt.UtcDateTime.ToString("yyyyMMdd-HHmmssfff'Z'")
    $snapshotPath = Join-Path `
        $resolvedDirectory `
        "$($TenantId.Guid)-m365-recommendation-status-$timestamp.json"
    if (Test-Path -LiteralPath $snapshotPath) {
        throw "Snapshot '$snapshotPath' already exists and will not be overwritten."
    }

    ConvertTo-Json -InputObject @($Results) -Depth 8 |
        Set-Content -LiteralPath $snapshotPath -Encoding utf8 -ErrorAction Stop
    (Resolve-Path -LiteralPath $snapshotPath -ErrorAction Stop).Path
}

function Get-CheckData {
    param([Parameter(Mandatory)] [string] $Name)
    if ($readFailures.ContainsKey($Name)) {
        throw "Cannot read ${Name}: $($readFailures[$Name])"
    }
    $data[$Name]
}

function Get-CheckedSecurityDefaults {
    $policy = Get-CheckData "SecurityDefaults"
    if ($policy.isEnabled -isnot [bool]) {
        throw "The security defaults response did not contain a Boolean isEnabled value."
    }
    $policy.isEnabled
}

function Test-ReportMfaGrant {
    param([Parameter(Mandatory)] $Policy)

    Test-SecureM365CaRequiresMfa $Policy
}

function Test-ReportPolicyScope {
    param(
        [Parameter(Mandatory)] $Policy,
        [ValidateSet("None", "SignIn", "User")] [string] $Risk = "None",
        [switch] $Legacy
    )

    Test-SecureM365CaPolicyScope -Policy $Policy -ApprovedExclusions $approvedExclusions `
        -Risk $Risk -Legacy:$Legacy
}

function Get-RegistrationCoverage {
    param([switch] $Administrators)

    $users = @(Get-CheckData "Users")
    if ($users.Count -eq 0) { throw "No users were returned; an empty tenant inventory cannot verify coverage." }
    $registration = @(Get-CheckData "Registration")
    $byId = @{}
    foreach ($row in $registration) {
        if ([string]::IsNullOrWhiteSpace($row.id) -or $byId.ContainsKey($row.id)) {
            throw "The registration report contains a missing or duplicate user ID."
        }
        $byId[$row.id] = $row
    }

    $directAdminIds = @()
    if ($Administrators) {
        $assignments = @(Get-CheckData "RoleAssignments")
        if (@($assignments | Where-Object { [string]::IsNullOrWhiteSpace($_.principalId) }).Count -gt 0) {
            throw "An active role assignment omitted its principal ID."
        }
        # Direct user assignments supplement the registration report. Non-user
        # principals cannot register MFA; group-based admins are identified by isAdmin.
        $directAdminIds = @(
            $assignments.principalId |
                Where-Object { $_ -in @($users.id) } |
                Sort-Object -Unique
        )
    }
    $selectedUsers = @(
        foreach ($user in $users) {
            if (
                [string]::IsNullOrWhiteSpace($user.id) -or
                $user.accountEnabled -isnot [bool] -or
                $user.userType -notin @("Member", "Guest")
            ) {
                throw "The user inventory is missing required identity, accountEnabled, or userType data."
            }
            if (-not $user.accountEnabled) { continue }
            $row = $byId[$user.id]
            if ($Administrators) {
                if ($user.id -notin $directAdminIds -and $row.isAdmin -ne $true) { continue }
            }
            elseif ($user.userType -ne "Member") {
                continue
            }
            [pscustomobject]@{ User = $user; Registration = $row }
        }
    )
    if ($selectedUsers.Count -eq 0) {
        throw "No enabled users were identified for this registration check; coverage cannot be verified."
    }
    $selectedUsers
}

function Get-MfaAssessment {
    param([switch] $Administrators)

    $securityDefaults = Get-CheckedSecurityDefaults
    $policyReadFailed = $securityDefaults -and $readFailures.ContainsKey("ConditionalAccess")
    $policies = @(if (-not $policyReadFailed) { Get-CheckData "ConditionalAccess" })
    $parameters = @{
        Policies = @($policies)
        SecurityDefaultsEnabled = $securityDefaults
        Administrators = $Administrators
        ApprovedExclusions = $approvedExclusions
    }
    $policyAssessment = Get-SecureM365MfaPolicyAssessment @parameters
    if ($Administrators -and $null -eq $policyAssessment.CoverageVerified) {
        try {
            $roles = @(Get-CheckData "RoleDefinitions")
            $assignments = @(Get-CheckData "RoleAssignments")
            if ($assignments.Count -eq 0) { throw "No active role assignments were returned." }
            $parameters.RequiredRoleIds = @(
                foreach ($assignment in $assignments) {
                    $role = @($roles | Where-Object { $_.id -eq $assignment.roleDefinitionId })
                    if (
                        $role.Count -ne 1 -or
                        $role[0].isBuiltIn -ne $true -or
                        [string]::IsNullOrWhiteSpace($role[0].templateId)
                    ) {
                        throw "An assigned role could not be resolved to a built-in template."
                    }
                    $role[0].templateId
                }
            ) | Select-Object -Unique
        }
        catch {
            $parameters.CoverageReadError = $_.Exception.Message
            Write-Warning "Administrator MFA coverage could not be evaluated: $($parameters.CoverageReadError)"
        }
        $policyAssessment = Get-SecureM365MfaPolicyAssessment @parameters
    }
    if ($policyReadFailed) {
        $policyAssessment.PolicyFound = $null
        $policyAssessment.EnabledPolicyFound = $null
        $policyAssessment.Evidence += " Conditional Access policy inventory is unavailable: $($readFailures['ConditionalAccess']). Security Defaults independently verifies the MFA configuration."
    }
    if ($policyAssessment.Status -ne "IMPLEMENTED") {
        return New-Assessment $policyAssessment.Status $policyAssessment.Evidence `
            -PolicyConfiguration $policyAssessment
    }

    try {
        $coverage = @(Get-RegistrationCoverage -Administrators:$Administrators)
        $missing = @($coverage | Where-Object { $_.Registration.isMfaCapable -isnot [bool] })
        $notCapable = @($coverage | Where-Object { $_.Registration.isMfaCapable -eq $false })
        $registrationNote = if ($notCapable.Count -gt 0 -or $missing.Count -gt 0) {
            "Registration advisory: $($notCapable.Count) of $($coverage.Count) checked enabled accounts are not reported MFA-capable and $($missing.Count) have missing data. Registration data can lag by up to 36 hours and does not determine the enabled-policy result."
        }
        else {
            "Registration advisory: all $($coverage.Count) checked enabled accounts are reported MFA-capable, including any emergency accounts."
        }
    }
    catch {
        $registrationNote = "Registration advisory: readiness data could not be verified and can lag by up to 36 hours. The enabled-policy result is unchanged. $($_.Exception.Message)"
    }

    New-Assessment "IMPLEMENTED" "$($policyAssessment.Evidence) $registrationNote" `
        -PolicyConfiguration $policyAssessment
}

function Get-RiskAssessment {
    param([Parameter(Mandatory)] [ValidateSet("SignIn", "User")] [string] $Risk)

    $parameters = @{
        Policies = @(Get-CheckData "ConditionalAccess")
        ApprovedExclusions = $approvedExclusions
    }
    if ($Risk -eq "SignIn") {
        $parameters.SignInRisk = $true
    }
    else {
        $parameters.UserRisk = $true
    }
    $policyAssessment = Get-SecureM365MfaPolicyAssessment @parameters
    New-Assessment $policyAssessment.Status $policyAssessment.Evidence `
        -PolicyConfiguration $policyAssessment
}

function Get-TeamsAssessment {
    param([string] $Property, $Expected)

    $policy = Get-CheckData "Teams"
    if ($null -eq $policy.$Property) {
        throw "Teams did not return '$Property' on the Global meeting policy."
    }
    if ($Expected -is [bool] -and $policy.$Property -isnot [bool]) {
        throw "Teams returned a non-Boolean '$Property' value for the Global meeting policy."
    }
    if ($policy.$Property -ne $Expected) {
        return New-Assessment "NOT-CONFIGURED" "Global: $Property is '$($policy.$Property)'; expected '$Expected'."
    }
    New-Assessment "IMPLEMENTED" "Global: $Property is '$Expected'."
}

function Get-SsprAssessment {
    try {
        $coverage = @(Get-RegistrationCoverage)
        $registered = @($coverage | Where-Object { $_.Registration.isSsprRegistered -eq $true })
        $notRegistered = @($coverage | Where-Object { $_.Registration.isSsprRegistered -eq $false })
        $missingRegistration = @(
            $coverage | Where-Object { $_.Registration.isSsprRegistered -isnot [bool] }
        )
        $capable = @($coverage | Where-Object { $_.Registration.isSsprCapable -eq $true })
        $notCapable = @($coverage | Where-Object { $_.Registration.isSsprCapable -eq $false })
        $missingCapability = @(
            $coverage | Where-Object { $_.Registration.isSsprCapable -isnot [bool] }
        )
        $registrationNote = "Registration note: $($registered.Count) of $($coverage.Count) enabled member accounts are reported SSPR-registered; $($notRegistered.Count) are not registered and $($missingRegistration.Count) have missing registration data. $($capable.Count) are reported SSPR-capable; $($notCapable.Count) are not capable and $($missingCapability.Count) have missing capability data. Registration data can lag by up to 36 hours."
    }
    catch {
        $registrationNote = "Registration note: readiness data could not be verified and can lag by up to 36 hours. $($_.Exception.Message)"
    }

    if (-not $SsprAllScopeConfirmed) {
        return New-Assessment "UNKNOWN" "Password reset > Properties = All has not been operator-confirmed. Microsoft Graph does not expose the exact None, Selected, or All scope. Confirm the setting in Entra, then rerun with -SsprAllScopeConfirmed. $registrationNote"
    }
    New-Assessment "IMPLEMENTED" "Password reset > Properties = All is recorded as operator-confirmed by the script default. $registrationNote"
}
#endregion

if ($UseGraphDeviceCode -and $UseGraphBrowserPkce) {
    throw "UseGraphDeviceCode and UseGraphBrowserPkce cannot be combined."
}

if (
    $PSVersionTable.PSEdition -ne "Core" -or
    $PSVersionTable.PSVersion -lt [version] "7.2"
) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw "Install App Installer from Microsoft, then install PowerShell 7.2 or later."
    }

    if ($PSCmdlet.ShouldProcess("this Windows client", "Install PowerShell 7 with WinGet")) {
        & winget.exe install --id Microsoft.PowerShell --source winget | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "WinGet failed with exit code $LASTEXITCODE."
        }
    }

    Write-Warning "Open PowerShell 7.2 or later by running pwsh.exe, then rerun AA-AssessM365Status.ps1. No assessment was performed."
    return
}

$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.Governance"
    "MicrosoftTeams"
    "ExchangeOnlineManagement"
)

foreach ($moduleName in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        if ($PSCmdlet.ShouldProcess($moduleName, "Install PowerShell module for the current user")) {
            $null = Install-Module `
                -Name $moduleName `
                -Scope CurrentUser `
                -Repository PSGallery `
                -ErrorAction Stop
        }
    }
}

if ($WhatIfPreference) {
    Write-Host "WhatIf: no tenant connections, assessment, or text report or snapshot writes were performed."
    return
}

$missingModules = @(
    $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
)
if ($missingModules.Count -gt 0) {
    throw "Required modules remain unavailable: $($missingModules -join ', '). Install them or rerun this script and approve installation."
}

$requiredModules |
    ForEach-Object {
        Get-Module -ListAvailable -Name $_ |
            Sort-Object Version -Descending |
            Select-Object -First 1 Name, Version, Path
    } |
    Out-Host

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module MicrosoftTeams -ErrorAction Stop

$assessmentTenantId = Resolve-SecureM365TenantId -TenantId $TenantId -PromptIfMissing
$additionalScopes = if ($ConsentForAllScripts) {
    Write-Host "Requesting the complete delegated Microsoft Graph scope set for scripts 00-99."
    @(Get-SecureM365GraphScopeSet -Profile AllScripts)
}
else {
    @()
}

$context = Connect-SecureM365Graph `
    -TenantId $assessmentTenantId `
    -AdditionalScopes $additionalScopes `
    -UseDeviceCode:$UseGraphDeviceCode `
    -UseBrowserPkce:$UseGraphBrowserPkce
if ($context.Environment -ne "Global") {
    throw "This script supports the Microsoft 365 worldwide cloud only."
}
$context |
    Select-Object Account, TenantId, AuthType, ContextScope, Scopes |
    Out-Host

$approvedExclusions = @{
    ApprovedExcludedUserIds  = @($ApprovedExcludedUserId | ForEach-Object { $_.Guid })
    ApprovedExcludedGroupIds = @($ApprovedExcludedGroupId | ForEach-Object { $_.Guid })
    ApprovedExcludedRoleIds  = @($ApprovedExcludedRoleId | ForEach-Object { $_.Guid })
}

$readers = [ordered]@{
    SecurityDefaults = {
        Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -ErrorAction Stop
    }
    ConditionalAccess = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
            -Headers @{ Prefer = "include-unknown-enum-members" }
    }
    Users = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled,userType&$top=999'
    }
    Registration = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    }
    # Role-management endpoints do not support $top; the collection helper follows nextLink.
    RoleDefinitions = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn'
    }
    RoleAssignments = {
        # The directory provider rejects appScopeId in $select; scope is directoryScopeId.
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId'
    }
    Authorization = {
        Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -ErrorAction Stop
    }
    Teams = {
        $teamsConnection = Connect-SecureM365Teams -TenantId $assessmentTenantId -ValidateMeetingPolicyAccess `
            -UseDeviceAuthentication:$UseTeamsDeviceAuthentication `
            -ApplicationId $TeamsApplicationId `
            -CertificateThumbprint $TeamsCertificateThumbprint `
            -CertificatePath $TeamsCertificatePath `
            -CertificatePassword $TeamsCertificatePassword
        $teamsConnection |
            Select-Object Account, Environment, Tenant, TenantId |
            Out-Host
        Get-SecureM365TeamsMeetingPolicy
    }
}
$data = @{}
$readFailures = @{}
foreach ($name in $readers.Keys) {
    try {
        $data[$name] = @(& $readers[$name])
    }
    catch {
        $readFailures[$name] = $_.Exception.Message
        if (-not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
            $readFailures[$name] += " $($_.ErrorDetails.Message)"
        }
        Write-Warning "Could not read ${name}: $($readFailures[$name]). Dependent checks will report UNKNOWN unless other evidence is sufficient."
    }
}

$checks = @(
    @{
        Title = "Ensure multifactor authentication is enabled for all users in administrative roles"
        Evaluate = { Get-MfaAssessment -Administrators }
    }
    @{
        Title = "Ensure multifactor authentication is enabled for all users"
        Evaluate = { Get-MfaAssessment }
    }
    @{
        Title = "Enable Conditional Access policies to block legacy authentication"
        Evaluate = {
            if (Get-CheckedSecurityDefaults) {
                return New-Assessment "IMPLEMENTED" "Security defaults is enabled and blocks legacy authentication."
            }
            $policies = @(Get-CheckData "ConditionalAccess")
            $blocking = @(
                $policies | Where-Object {
                    (Test-ReportPolicyScope -Policy $_ -Legacy) -and
                    (Test-SecureM365CaTargetsAllUsers $_) -and
                    @($_.grantControls.builtInControls) -contains "block"
                }
            )
            if ($blocking.Count -gt 0) {
                return New-Assessment "IMPLEMENTED" "Enforced legacy-authentication block: $($blocking.displayName -join ', ')."
            }
            $narrowBlocks = @($policies | Where-Object {
                $_.state -eq "enabled" -and @($_.grantControls.builtInControls) -contains "block"
            })
            if ($narrowBlocks.Count -gt 0) {
                return New-Assessment "UNKNOWN" "Block policies exist, but coverage of both legacy client types, all users/resources, and only approved exclusions was not verified."
            }
            New-Assessment "NOT-CONFIGURED" "Security defaults is disabled and no enabled Conditional Access block policy was found."
        }
    }
    @{
        Title = "Enable Microsoft Entra ID Identity Protection sign-in risk policies"
        Evaluate = { Get-RiskAssessment -Risk SignIn }
    }
    @{
        Title = "Enable Microsoft Entra ID Identity Protection user risk policies"
        Evaluate = { Get-RiskAssessment -Risk User }
    }
    @{
        Title = "Ensure user consent to apps accessing company data on their behalf is not allowed"
        Evaluate = {
            $policy = Get-CheckData "Authorization"
            $assigned = $policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
            if ($null -eq $assigned) { throw "The authorization policy did not return permissionGrantPoliciesAssigned." }
            $selfConsent = @($assigned | Where-Object {
                $_ -match '(?i)^managePermissionGrantsForSelf\.' -or $_ -match '(?i)(^|\.)user-default'
            })
            if ($selfConsent.Count -gt 0) {
                return New-Assessment "NOT-CONFIGURED" "User consent is permitted by: $($selfConsent -join ', ')."
            }
            New-Assessment "IMPLEMENTED" "No default-user self-consent policy is assigned. Existing consent grants are not revoked by this setting."
        }
    }
    @{
        Title = "Only invited users should be automatically admitted to Teams meetings"
        Evaluate = { Get-TeamsAssessment -Property AutoAdmittedUsers -Expected "InvitedUsers" }
    }
    @{
        Title = "Configure which users are allowed to present in Teams meetings"
        Evaluate = { Get-TeamsAssessment -Property DesignatedPresenterRoleMode -Expected "OrganizerOnlyUserOverride" }
    }
    @{
        Title = "Restrict anonymous users from joining meetings"
        Evaluate = { Get-TeamsAssessment -Property AllowAnonymousUsersToJoinMeeting -Expected $false }
    }
    @{
        Title = "Ensure 'Self service password reset enabled' is set to 'All'"
        Evaluate = { Get-SsprAssessment }
    }
)

$checkedAt = [datetimeoffset]::UtcNow
$reportHeader = @(
    "`nMicrosoft 365 live recommendation status"
    "Tenant: $($assessmentTenantId.Guid) | Checked at: $($checkedAt.ToString('u'))"
    "MFA results check enabled configuration; complete coverage and registration are advisory."
    "Registration data can lag by up to 36 hours. UNKNOWN means not verified, not necessarily unconfigured.`n"
) -join [Environment]::NewLine
Write-Host $reportHeader
$results = @(
    for ($index = 0; $index -lt $checks.Count; $index++) {
        $check = $checks[$index]
        try {
            $assessment = & $check.Evaluate
        }
        catch {
            Write-Warning "Check $($index + 1) failed: $($_.Exception.Message)"
            $assessment = New-Assessment "UNKNOWN" "CHECK FAILED: $($_.Exception.Message)"
        }
        [pscustomobject]@{
            Number         = $index + 1
            Recommendation = $check.Title
            Status         = $assessment.Status
            Evidence       = $assessment.Evidence
            # Retained for consumers of earlier script versions.
            Details        = $assessment.Evidence
            PolicyConfiguration = $assessment.PolicyConfiguration
            TenantId       = $assessmentTenantId.Guid
            CheckedAt      = $checkedAt
        }
    }
)

$snapshotPath = Save-RecommendationSnapshot `
    -Results $results `
    -TenantId $assessmentTenantId `
    -CheckedAt $checkedAt `
    -Directory $SnapshotDirectory

$implemented = @($results | Where-Object Status -eq "IMPLEMENTED").Count
$notConfigured = @($results | Where-Object Status -eq "NOT-CONFIGURED").Count
$unknown = @($results | Where-Object Status -eq "UNKNOWN").Count
$reportText = @(
    $results | Format-Table Number, Status, Recommendation, Evidence -Wrap | Out-String -Stream
    "`nSummary: $implemented implemented, $notConfigured not configured, $unknown unknown ($($checks.Count) recommendations)."
    "Snapshot: $snapshotPath"
) -join [Environment]::NewLine
Write-Host $reportText

$reportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("hardening-results.txt")
if (Test-Path -LiteralPath $reportPath -PathType Container) {
    throw "Final results path '$reportPath' is a directory."
}
@($reportHeader, $reportText) -join [Environment]::NewLine |
    Set-Content -LiteralPath $reportPath -Encoding utf8 -ErrorAction Stop
if ($PassThru) { $results }
