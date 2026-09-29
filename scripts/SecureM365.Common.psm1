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

    $readScopes = @(
        "AuditLog.Read.All"
        "Policy.Read.All"
        "RoleManagement.Read.Directory"
        "SecurityEvents.Read.All"
        "User.Read.All"
    )
    $scopes = @(
        $readScopes
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
        [switch] $ValidateMeetingPolicyAccess
    )

    $connectParameters = @{
        TenantId    = $TenantId.Guid
        ErrorAction = "Stop"
    }
    if ($UseDeviceAuthentication) {
        $connectParameters.UseDeviceAuthentication = $true
    }

    $connection = Connect-MicrosoftTeams @connectParameters
    if ([string] $connection.TenantId -ne $TenantId.Guid) {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        throw "Microsoft Teams connected to tenant '$($connection.TenantId)' instead of '$($TenantId.Guid)'."
    }

    if ($ValidateMeetingPolicyAccess) {
        try {
            $globalPolicy = @(Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop)
            if ($globalPolicy.Count -ne 1 -or $globalPolicy[0].Identity -ne "Global") {
                throw "Microsoft Teams did not return the Global meeting policy."
            }
        }
        catch {
            $details = $_.Exception.Message
            if (-not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
                $details += " $($_.ErrorDetails.Message)"
            }
            throw [System.InvalidOperationException]::new(
                "Microsoft Teams connected to tenant '$($TenantId.Guid)', but reading the Global meeting policy failed. " +
                "For Forbidden/Access Denied, verify the Teams account has an active role permitted to read meeting policies " +
                "(for example, Teams Communications Administrator). Activate PIM if needed and allow role changes to propagate, " +
                "then run Disconnect-MicrosoftTeams and rerun script 01 with -IncludeTeams. Graph consent does not grant Teams permissions. " +
                "Original error: $details",
                $_.Exception
            )
        }
    }

    $connection
}

function Test-SecureM365TeamsServicePlanName {
    param([AllowNull()][string] $ServicePlanName)
    $ServicePlanName -match '^(?i:TEAMS|MICROSOFT_TEAMS|MCOIMP|MCOMEETADV|MCOEV|MCOCAP|MESH)'
}

function Test-SecureM365CoreTeamsServicePlanName {
    param([AllowNull()][string] $ServicePlanName)
    $ServicePlanName -match '^(?i:TEAMS(?:\d|_|$))'
}

function Get-SecureM365TeamsProvisioningStatus {
    [CmdletBinding()]
    param()

    $skus = @(Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,servicePlans')
    foreach ($sku in $skus) {
        if (
            [string]::IsNullOrWhiteSpace([string] $sku.skuId) -or
            [string]::IsNullOrWhiteSpace([string] $sku.skuPartNumber) -or
            [string]::IsNullOrWhiteSpace([string] $sku.capabilityStatus) -or
            $null -eq $sku.servicePlans
        ) {
            throw "Graph returned an incomplete subscribed SKU inventory."
        }
        foreach ($plan in @($sku.servicePlans)) {
            if (
                [string]::IsNullOrWhiteSpace([string] $plan.servicePlanId) -or
                [string]::IsNullOrWhiteSpace([string] $plan.servicePlanName) -or
                [string]::IsNullOrWhiteSpace([string] $plan.provisioningStatus)
            ) {
                throw "Graph returned an incomplete tenant service-plan inventory."
            }
        }
    }

    $tenantTeamsPlans = @(
        foreach ($sku in $skus) {
            foreach ($plan in @($sku.servicePlans)) {
                if (Test-SecureM365TeamsServicePlanName $plan.servicePlanName) {
                    [pscustomobject]@{
                        SkuId              = [string] $sku.skuId
                        SkuPartNumber      = [string] $sku.skuPartNumber
                        SkuCapabilityStatus = [string] $sku.capabilityStatus
                        ServicePlanId      = [string] $plan.servicePlanId
                        ServicePlanName    = [string] $plan.servicePlanName
                        ProvisioningStatus = [string] $plan.provisioningStatus
                    }
                }
            }
        }
    )
    $enabledTenantTeamsPlans = @(
        $tenantTeamsPlans | Where-Object {
            Test-SecureM365CoreTeamsServicePlanName $_.ServicePlanName
        } | Where-Object {
            $_.SkuCapabilityStatus -in @("Enabled", "Warning") -and
            $_.ProvisioningStatus -eq "Success"
        }
    )
    if ($tenantTeamsPlans.Count -eq 0 -or @(
        $tenantTeamsPlans | Where-Object { $_.SkuCapabilityStatus -in @("Enabled", "Warning") }
    ).Count -eq 0) {
        return [pscustomobject]@{
            Status = "FAILED"
            Code = "TEAMS_TENANT_ABSENT"
            Details = "No enabled tenant subscription containing Microsoft Teams service plans was found."
            TenantTeamsPlanCount = $tenantTeamsPlans.Count
            TenantReadyPlanCount = 0
            UserTeamsPlanCount = 0
            UserReadyPlanCount = 0
        }
    }
    if ($enabledTenantTeamsPlans.Count -eq 0) {
        return [pscustomobject]@{
            Status = "FAILED"
            Code = "TEAMS_TENANT_PLANS_UNAVAILABLE"
            Details = "The tenant has Microsoft Teams service plans, but none are provisioned successfully."
            TenantTeamsPlanCount = $tenantTeamsPlans.Count
            TenantReadyPlanCount = 0
            UserTeamsPlanCount = 0
            UserReadyPlanCount = 0
        }
    }

    $licenseDetails = @(Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/me/licenseDetails?$select=skuId,skuPartNumber,servicePlans')
    foreach ($license in $licenseDetails) {
        if (
            [string]::IsNullOrWhiteSpace([string] $license.skuId) -or
            [string]::IsNullOrWhiteSpace([string] $license.skuPartNumber) -or
            $null -eq $license.servicePlans
        ) {
            throw "Graph returned an incomplete user license-details inventory."
        }
        foreach ($plan in @($license.servicePlans)) {
            if (
                [string]::IsNullOrWhiteSpace([string] $plan.servicePlanId) -or
                [string]::IsNullOrWhiteSpace([string] $plan.servicePlanName) -or
                [string]::IsNullOrWhiteSpace([string] $plan.provisioningStatus)
            ) {
                throw "Graph returned an incomplete user license service-plan inventory."
            }
        }
    }

    $user = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,assignedPlans' `
        -ErrorAction Stop
    if (
        [string]::IsNullOrWhiteSpace([string] $user.id) -or
        [string]::IsNullOrWhiteSpace([string] $user.userPrincipalName) -or
        $null -eq $user.assignedPlans
    ) {
        throw "Graph returned an incomplete signed-in user assigned-plan inventory."
    }
    foreach ($plan in @($user.assignedPlans)) {
        if (
            [string]::IsNullOrWhiteSpace([string] $plan.servicePlanId) -or
            [string]::IsNullOrWhiteSpace([string] $plan.service) -or
            [string]::IsNullOrWhiteSpace([string] $plan.capabilityStatus)
        ) {
            throw "Graph returned an incomplete assigned-plan inventory."
        }
    }

    $userLicenseTeamsPlans = @(
        foreach ($license in $licenseDetails) {
            foreach ($plan in @($license.servicePlans)) {
                if (Test-SecureM365TeamsServicePlanName $plan.servicePlanName) {
                    [pscustomobject]@{
                        SkuPartNumber      = [string] $license.skuPartNumber
                        ServicePlanId      = [string] $plan.servicePlanId
                        ServicePlanName    = [string] $plan.servicePlanName
                        ProvisioningStatus = [string] $plan.provisioningStatus
                    }
                }
            }
        }
    )
    $enabledAssignedPlanIds = @(
        $user.assignedPlans |
        Where-Object { $_.capabilityStatus -eq "Enabled" } |
        ForEach-Object { [string] $_.servicePlanId }
    )
    $readyUserTeamsPlans = @(
        $userLicenseTeamsPlans | Where-Object {
            Test-SecureM365CoreTeamsServicePlanName $_.ServicePlanName
        } | Where-Object {
            $_.ProvisioningStatus -eq "Success" -and
            $_.ServicePlanId -in $enabledAssignedPlanIds
        }
    )
    if ($userLicenseTeamsPlans.Count -eq 0 -or $readyUserTeamsPlans.Count -eq 0) {
        return [pscustomobject]@{
            Status = "FAILED"
            Code = "TEAMS_USER_UNLICENSED_OR_UNPROVISIONED"
            Details = "The signed-in administrator has no Microsoft Teams service plan that is both provisioned successfully in licenseDetails and Enabled in assignedPlans."
            TenantTeamsPlanCount = $tenantTeamsPlans.Count
            TenantReadyPlanCount = $enabledTenantTeamsPlans.Count
            UserTeamsPlanCount = $userLicenseTeamsPlans.Count
            UserReadyPlanCount = $readyUserTeamsPlans.Count
        }
    }

    [pscustomobject]@{
        Status = "PASSED"
        Code = "TEAMS_LICENSED_AND_PROVISIONED"
        Details = "Microsoft Teams is licensed for the tenant, and the signed-in administrator has $($readyUserTeamsPlans.Count) provisioned and enabled Teams service plan(s)."
        TenantTeamsPlanCount = $tenantTeamsPlans.Count
        TenantReadyPlanCount = $enabledTenantTeamsPlans.Count
        UserTeamsPlanCount = $userLicenseTeamsPlans.Count
        UserReadyPlanCount = $readyUserTeamsPlans.Count
    }
}

function Get-SecureM365TeamsMeetingPolicy {
    [CmdletBinding(DefaultParameterSetName = "SelectedPolicies")]
    param(
        [Parameter(ParameterSetName = "SelectedPolicies")]
        [ValidateNotNullOrEmpty()]
        [string[]] $PolicyIdentity = @("Global"),

        [Parameter(Mandatory, ParameterSetName = "AllPolicies")]
        [switch] $AllPolicies
    )

    $policies = @(
        if ($AllPolicies) {
            Get-CsTeamsMeetingPolicy -ErrorAction Stop
        }
        else {
            foreach ($identity in $PolicyIdentity) {
                if ([string]::IsNullOrWhiteSpace($identity)) {
                    throw "Supply a nonempty Teams meeting policy identity."
                }
                $matches = @(Get-CsTeamsMeetingPolicy -Identity $identity -ErrorAction Stop)
                $expectedIdentity = if ($identity -eq "Global") {
                    "Global"
                }
                else {
                    "Tag:" + ($identity -replace '^Tag:', '')
                }
                if ($matches.Count -ne 1 -or [string] $matches[0].Identity -ne $expectedIdentity) {
                    throw "Teams did not return exactly the requested meeting policy '$identity'. No policies were changed."
                }
                $matches[0]
            }
        }
    )

    $seen = @{}
    foreach ($policy in $policies) {
        $identity = [string] $policy.Identity
        if ([string]::IsNullOrWhiteSpace($identity) -or $seen.ContainsKey($identity)) {
            throw "Teams returned a missing or duplicate meeting policy identity. No policies were changed."
        }
        $seen[$identity] = $true
    }
    if ($policies.Count -eq 0 -or ($AllPolicies -and -not $seen.ContainsKey("Global"))) {
        throw "Teams returned an empty or incomplete meeting policy inventory (Global is required for -AllPolicies). No policies were changed."
    }

    $policies
}

function Get-SecureM365TeamsMeetingPolicyUpdateError {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)]
        [string] $PolicyIdentity,

        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $details = $ErrorRecord.Exception.Message
    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $details += " $($ErrorRecord.ErrorDetails.Message)"
    }
    # Ordinary authorization and validation failures must retain their original errors.
    if ($details -notmatch "Tenant Admin can't modify first party documents") {
        return $ErrorRecord
    }

    $message = "Teams policy '$PolicyIdentity' is a Microsoft-managed read-only preset. " +
        "It cannot be edited by a tenant administrator; adding roles will not fix this error. " +
        "Use -PolicyIdentity Global or explicitly select a tenant-created custom policy. " +
        "Review user/group assignments before replacing a preset with a compliant policy. " +
        "Execution stopped at this policy; remaining policies were not processed and earlier updates were not rolled back. " +
        "Script 99 still audits read-only and unused presets. Original Teams error: $details"
    [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($message, $ErrorRecord.Exception),
        "SecureM365TeamsReadOnlyPolicy",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $PolicyIdentity
    )
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

function Get-SecureM365EnabledConditionalAccessPolicy {
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999' |
        Where-Object { $_.state -eq "enabled" }
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
    (@($Policy.conditions.applications.excludeApplications).Count -eq 0)
}

function Test-SecureM365CaRequiresMfa {
    param([Parameter(Mandatory)] $Policy)

    $builtInControls = @($Policy.grantControls.builtInControls)
    $strength = $Policy.grantControls.authenticationStrength

    ($builtInControls -contains "mfa") -or
    ($strength.id -eq "00000000-0000-0000-0000-000000000002") -or
    ($strength.requirementsSatisfied -eq "mfa")
}

function Test-SecureM365CaUsesEveryTimeSignInFrequency {
    param([Parameter(Mandatory)] $Policy)

    $frequency = $Policy.sessionControls.signInFrequency
    ($null -ne $frequency) -and
    ($frequency.isEnabled -eq $true) -and
    ($frequency.frequencyInterval -eq "everyTime")
}

function Get-SecureM365SecurityDefaultsEnabled {
    $policy = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
        -ErrorAction Stop
    $policy.isEnabled -eq $true
}

function Reset-SecureM365ScoreCache {
    $script:SecureScoreProfiles = $null
    $script:LatestSecureScore = $null
}

function Test-SecureM365ScoreAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [string] $ControlName
    )

    if ($null -eq $script:SecureScoreProfiles) {
        $script:SecureScoreProfiles = @(
            Get-SecureM365GraphCollection `
                -Uri 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=999'
        )
    }

    if ($null -eq $script:LatestSecureScore) {
        $page = Invoke-MgGraphRequest `
            -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=30' `
            -ErrorAction Stop
        $script:LatestSecureScore = @(
            $page.value |
            Where-Object { $_.vendorInformation.vendor -eq "Microsoft" }
        ) |
            Sort-Object { [datetimeoffset] $_.createdDateTime } -Descending |
            Select-Object -First 1
    }

    if ($null -eq $script:LatestSecureScore) {
        throw "Microsoft Graph returned no Microsoft Secure Score snapshots."
    }

    $profile = @(
        $script:SecureScoreProfiles |
        Where-Object {
            $_.id -eq $ControlName -and
            $_.vendorInformation.vendor -eq "Microsoft"
        }
    ) | Select-Object -First 1

    if ($null -eq $profile) {
        $profile = @(
            $script:SecureScoreProfiles |
            Where-Object {
                $_.title -eq $Title -and
                $_.vendorInformation.vendor -eq "Microsoft"
            }
        ) | Select-Object -First 1
    }

    if ($null -eq $profile) {
        return [pscustomobject]@{
            Action   = $Title
            Resolved = $false
            Details  = "The Microsoft Secure Score control profile was not found."
        }
    }

    $control = @(
        $script:LatestSecureScore.controlScores |
        Where-Object { $_.controlName -eq $profile.id }
    ) | Select-Object -First 1

    $currentScore = if ($null -eq $control) { 0.0 } else { [double] $control.score }
    $maxScore = [double] $profile.maxScore
    $controlFound = $null -ne $control

    [pscustomobject]@{
        Action          = $Title
        ControlName     = $profile.id
        ControlFound    = $controlFound
        CurrentScore    = $currentScore
        MaximumScore    = $maxScore
        Resolved        = $controlFound -and ($currentScore -ge $maxScore)
        ScoreSnapshotAt = $script:LatestSecureScore.createdDateTime
        Details         = if ($controlFound) {
            $null
        }
        else {
            "The control is not present in the latest Secure Score snapshot."
        }
    }
}

Export-ModuleMember -Function @(
    "Resolve-SecureM365TenantId"
    "Connect-SecureM365Graph"
    "Connect-SecureM365Teams"
    "Get-SecureM365TeamsProvisioningStatus"
    "Get-SecureM365TeamsMeetingPolicy"
    "Get-SecureM365TeamsMeetingPolicyUpdateError"
    "Get-SecureM365GraphCollection"
    "Get-SecureM365EnabledConditionalAccessPolicy"
    "New-SecureM365ConditionalAccessPolicy"
    "Test-SecureM365CaTargetsAllUsers"
    "Test-SecureM365CaHasOnlyApprovedExclusions"
    "Test-SecureM365CaTargetsAllResources"
    "Test-SecureM365CaRequiresMfa"
    "Test-SecureM365CaUsesEveryTimeSignInFrequency"
    "Get-SecureM365SecurityDefaultsEnabled"
    "Reset-SecureM365ScoreCache"
    "Test-SecureM365ScoreAction"
)
