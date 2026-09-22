$teamsConnection = Connect-MicrosoftTeams -TenantId $TenantId
$teamsTenantId = [string] $teamsConnection.TenantId

if ($teamsTenantId -ne $TenantId) {
    Disconnect-MicrosoftTeams
    throw "Microsoft Teams connected to tenant '$teamsTenantId' instead of '$TenantId'."
}

$teamsConnection |
    Select-Object Account, Environment, Tenant, TenantId
