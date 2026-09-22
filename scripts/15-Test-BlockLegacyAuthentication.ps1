#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [guid[]] $ApprovedExcludedUserId = @(),
    [guid[]] $ApprovedExcludedGroupId = @(),
    [guid[]] $ApprovedExcludedRoleId = @(),
    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$approvedExclusions = @{
    ApprovedExcludedUserIds  = @(
        $ApprovedExcludedUserId | ForEach-Object { $_.Guid }
    )
    ApprovedExcludedGroupIds = @(
        $ApprovedExcludedGroupId | ForEach-Object { $_.Guid }
    )
    ApprovedExcludedRoleIds  = @(
        $ApprovedExcludedRoleId | ForEach-Object { $_.Guid }
    )
}
$blockingPolicies = @(
    Get-SecureM365EnabledConditionalAccessPolicy |
    Where-Object {
        $clientApps = @($_.conditions.clientAppTypes)
        $controls = @($_.grantControls.builtInControls)

        (Test-SecureM365CaTargetsAllUsers $_) -and
        (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $_ @approvedExclusions) -and
        (Test-SecureM365CaTargetsAllResources $_) -and
        ($clientApps -contains "exchangeActiveSync") -and
        ($clientApps -contains "other") -and
        ($controls -contains "block")
    }
)
$securityDefaults = Get-SecureM365SecurityDefaultsEnabled

[pscustomobject]@{
    Control          = "Block legacy authentication"
    SecurityDefaults = $securityDefaults
    MatchingPolicies = @($blockingPolicies.displayName)
    Resolved         = $securityDefaults -or ($blockingPolicies.Count -gt 0)
}

Test-SecureM365ScoreAction `
    -Title "Enable Conditional Access policies to block legacy authentication" `
    -ControlName "BlockLegacyAuthentication"
