$TenantId = "<microsoft-entra-tenant-guid>"

$parsedTenantId = [guid]::Empty
if (-not [guid]::TryParse($TenantId, [ref] $parsedTenantId)) {
    throw "Replace TenantId with the Microsoft Entra tenant GUID."
}
$TenantId = $parsedTenantId.Guid

$script:SecureScoreTenantId = $TenantId
$script:SecureScoreReadScopes = @(
    "AuditLog.Read.All"
    "Policy.Read.All"
    "RoleManagement.Read.Directory"
    "SecurityEvents.Read.All"
    "User.Read.All"
)

function Connect-SecureScoreGraph {
    [CmdletBinding()]
    param(
        [string[]] $AdditionalScopes = @(),
        [switch] $UseDeviceCode
    )

    if ([string]::IsNullOrWhiteSpace($script:SecureScoreTenantId)) {
        throw "Set SecureScoreTenantId before connecting."
    }

    $scopes = @(
        $script:SecureScoreReadScopes
        $AdditionalScopes
    ) | Sort-Object -Unique

    $connectParameters = @{
        TenantId     = $script:SecureScoreTenantId
        Scopes       = [string[]] $scopes
        ContextScope = "Process"
        NoWelcome    = $true
        ErrorAction  = "Stop"
    }
    if ($UseDeviceCode) {
        $connectParameters.UseDeviceCode = $true
    }

    Connect-MgGraph @connectParameters
    $context = Get-MgContext

    if (
        $null -eq $context -or
        $context.TenantId -ne $script:SecureScoreTenantId -or
        $context.AuthType -ne "Delegated"
    ) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "Microsoft Graph did not connect to the expected tenant with delegated authentication."
    }

    $missingScopes = @(
        $scopes |
        Where-Object { $_ -notin $context.Scopes }
    )
    if ($missingScopes.Count -gt 0) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "The connection is missing consented scopes: $($missingScopes -join ', ')"
    }

    $context |
        Select-Object Account, TenantId, AuthType, ContextScope, Scopes
}

Connect-SecureScoreGraph
