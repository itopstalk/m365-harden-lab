#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$modulePath = Join-Path $scriptsRoot "SecureM365.Common.psm1"
$parseErrors = $null
$moduleAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref] $null, [ref] $parseErrors
)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }

$authenticationFunctions = @(
    "ConvertTo-SecureM365Base64Url"
    "ConvertFrom-SecureM365JwtPayload"
    "Resolve-SecureM365TenantId"
    "Get-SecureM365OAuthAuthorizationCode"
    "Get-SecureM365ValidatedBrowserToken"
    "Invoke-SecureM365BrowserPkce"
    "Connect-SecureM365Graph"
)
foreach ($statement in $moduleAst.EndBlock.Statements) {
    if (
        $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $statement.Name -in $authenticationFunctions
    ) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}

function Connect-MgGraph {
    [CmdletBinding()]
    param(
        [string] $TenantId,
        [string[]] $Scopes,
        [string] $ContextScope,
        [switch] $NoWelcome,
        [switch] $UseDeviceCode,
        [securestring] $AccessToken
    )
    throw "Unmocked Graph connection."
}
function Get-MgContext { [CmdletBinding()] param() throw "Unmocked Graph context." }
function Disconnect-MgGraph { [CmdletBinding()] param() throw "Unmocked Graph disconnect." }
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri)
    throw "Unmocked Graph request."
}

Describe "SecureM365 Graph authentication (offline)" {
    BeforeEach {
        $script:tenant = "11111111-1111-4111-8111-111111111111"
        $script:connectCount = 0
        $script:disconnectCount = 0
        $script:context = $null
        $script:pkceCount = 0
        Remove-Variable SecureM365GraphContextMetadata -Scope Global -ErrorAction SilentlyContinue

        Mock Get-MgContext { $script:context }
        Mock Disconnect-MgGraph { $script:disconnectCount++ }
        Mock Invoke-MgGraphRequest {
            @{
                id = "22222222-2222-4222-8222-222222222222"
                userPrincipalName = "lab-admin@example.com"
            }
        }
        Mock Connect-MgGraph {
            param($TenantId, $Scopes, $ContextScope, $NoWelcome, $UseDeviceCode, $AccessToken)
            $script:connectCount++
            $script:context = if ($AccessToken) {
                [pscustomobject]@{
                    TenantId = ""
                    Scopes = @()
                    Account = "lab-admin@example.com"
                    AuthType = "UserProvidedAccessToken"
                    Environment = "Global"
                    ContextScope = "Process"
                }
            }
            else {
                [pscustomobject]@{
                    TenantId = $TenantId
                    Scopes = @($Scopes)
                    Account = "lab-admin@example.com"
                    AuthType = "Delegated"
                    Environment = "Global"
                    ContextScope = $ContextScope
                }
            }
        }
        Mock Invoke-SecureM365BrowserPkce {
            param($TenantId, $Scopes)
            $script:pkceCount++
            [pscustomobject]@{
                AccessToken = "opaque-or-encrypted-access-token"
                Scopes = @($Scopes)
                TenantId = $TenantId.Guid
            }
        }
    }

    It "accepts an explicit tenant GUID" {
        (Resolve-SecureM365TenantId $script:tenant).Guid | Should Be $script:tenant
    }

    It "rejects a missing, invalid, or empty tenant GUID" {
        { Resolve-SecureM365TenantId -TenantId "" } | Should Throw "TenantId must"
        { Resolve-SecureM365TenantId -TenantId "not-a-guid" } | Should Throw "TenantId must"
        {
            Resolve-SecureM365TenantId -TenantId "00000000-0000-0000-0000-000000000000"
        } | Should Throw "TenantId must"
    }

    It "validates OAuth state before returning the authorization code" {
        $query = [Collections.Specialized.NameValueCollection]::new()
        $query.Add("state", "expected")
        $query.Add("code", "one-time-code")
        Get-SecureM365OAuthAuthorizationCode $query "expected" | Should Be "one-time-code"
        { Get-SecureM365OAuthAuthorizationCode $query "different" } | Should Throw "state validation failed"
    }

    It "reports OAuth errors and missing codes" {
        $errorQuery = [Collections.Specialized.NameValueCollection]::new()
        $errorQuery.Add("state", "expected")
        $errorQuery.Add("error", "access_denied")
        $errorQuery.Add("error_description", "The user cancelled.")
        { Get-SecureM365OAuthAuthorizationCode $errorQuery "expected" } | Should Throw "access_denied"

        $emptyQuery = [Collections.Specialized.NameValueCollection]::new()
        $emptyQuery.Add("state", "expected")
        { Get-SecureM365OAuthAuthorizationCode $emptyQuery "expected" } | Should Throw "no authorization code"
    }

    It "validates browser-token tenant, nonce, expiry, and granted scopes without decoding the access token" {
        $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
        $nonce = "fixture-nonce"
        $claims = @{
            aud = $clientId
            iss = "https://login.microsoftonline.com/$($script:tenant)/v2.0"
            tid = $script:tenant
            nonce = $nonce
            exp = [DateTimeOffset]::UtcNow.AddMinutes(5).ToUnixTimeSeconds()
        } | ConvertTo-Json -Compress
        $payload = ConvertTo-SecureM365Base64Url ([Text.Encoding]::UTF8.GetBytes($claims))
        $token = [pscustomobject]@{
            access_token = "opaque-or-encrypted-access-token"
            id_token = "header.$payload.signature"
            scope = "Policy.Read.All User.Read.All"
        }

        $validated = Get-SecureM365ValidatedBrowserToken `
            -TokenResponse $token `
            -TenantId $script:tenant `
            -Scopes @("Policy.Read.All", "User.Read.All") `
            -ClientId $clientId `
            -Nonce $nonce
        $validated.AccessToken | Should Be "opaque-or-encrypted-access-token"

        {
            Get-SecureM365ValidatedBrowserToken -TokenResponse $token `
                -TenantId "33333333-3333-4333-8333-333333333333" `
                -Scopes @("Policy.Read.All") -ClientId $clientId -Nonce $nonce
        } | Should Throw "ID-token validation failed"
        {
            Get-SecureM365ValidatedBrowserToken -TokenResponse $token `
                -TenantId $script:tenant -Scopes @("Directory.Read.All") `
                -ClientId $clientId -Nonce $nonce
        } | Should Throw "did not grant"
    }

    It "does not combine device code and browser PKCE" {
        {
            Connect-SecureM365Graph -TenantId $script:tenant -UseDeviceCode -UseBrowserPkce
        } | Should Throw "cannot be combined"
    }

    It "reuses a matching delegated context after a Graph user probe" {
        $script:context = [pscustomobject]@{
            TenantId = $script:tenant
            Scopes = @(
                "AuditLog.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory",
                "SecurityEvents.Read.All", "User.Read.All"
            )
            Account = "lab-admin@example.com"
            AuthType = "Delegated"
            Environment = "Global"
            ContextScope = "Process"
        }
        $result = Connect-SecureM365Graph -TenantId $script:tenant
        $result | Should Be $script:context
        $script:connectCount | Should Be 0
        Assert-MockCalled Invoke-MgGraphRequest -Times 1
    }

    It "does not reuse a wrong-tenant context" {
        $script:context = [pscustomobject]@{
            TenantId = "33333333-3333-4333-8333-333333333333"
            Scopes = @()
            AuthType = "Delegated"
        }
        $result = Connect-SecureM365Graph -TenantId $script:tenant
        $script:connectCount | Should Be 1
        $result.TenantId | Should Be $script:tenant
    }

    It "does not reuse a context missing required scopes" {
        $script:context = [pscustomobject]@{
            TenantId = $script:tenant
            Scopes = @("User.Read.All")
            AuthType = "Delegated"
        }
        Connect-SecureM365Graph -TenantId $script:tenant | Out-Null
        $script:connectCount | Should Be 1
    }

    It "connects with an opaque browser-PKCE access token without decoding it" {
        $result = Connect-SecureM365Graph -TenantId $script:tenant -UseBrowserPkce
        $script:pkceCount | Should Be 1
        $script:connectCount | Should Be 1
        $result.AuthType | Should Be "UserProvidedAccessToken"
        $result.TenantId | Should Be $script:tenant
        ($result.Scopes -contains "Policy.Read.All") | Should Be $true
    }

    It "reuses validated process metadata when an opaque-token context exposes no claims" {
        Connect-SecureM365Graph -TenantId $script:tenant -UseBrowserPkce | Out-Null
        $script:context = [pscustomobject]@{
            TenantId = ""
            Scopes = @()
            Account = "lab-admin@example.com"
            AuthType = "UserProvidedAccessToken"
            Environment = "Global"
            ContextScope = "Process"
        }

        $result = Connect-SecureM365Graph -TenantId $script:tenant
        $script:connectCount | Should Be 1
        $script:pkceCount | Should Be 1
        $result.TenantId | Should Be $script:tenant
        ($result.Scopes -contains "Policy.Read.All") | Should Be $true
    }

    It "uses device-code authentication when selected" {
        Connect-SecureM365Graph -TenantId $script:tenant -UseDeviceCode | Out-Null
        Assert-MockCalled Connect-MgGraph -Times 1 -ParameterFilter { $UseDeviceCode }
        $script:pkceCount | Should Be 0
    }
}

Describe "Authentication secret protections" {
    It "contains no password or credential-file input path" {
        $source = Get-Content $modulePath -Raw
        $source | Should Not Match '(?i)\[securestring\]\s*\$password'
        $source | Should Not Match '(?i)Get-Content\s+.*credentials\.txt'
        $source | Should Not Match '(?i)Read-Host\s+.*password'
    }

    It "ignores common local secret files" {
        $ignore = @(Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) ".gitignore"))
        ($ignore -contains "credentials.txt") | Should Be $true
        ($ignore -contains "*.token") | Should Be $true
        ($ignore -contains ".env") | Should Be $true
    }

    It "uses PKCE S256 and a bounded callback wait" {
        $source = Get-Content $modulePath -Raw
        $source | Should Match 'code_challenge_method\s*=\s*"S256"'
        $source | Should Match 'FromSeconds\(\$TimeoutSeconds\)'
    }
}
