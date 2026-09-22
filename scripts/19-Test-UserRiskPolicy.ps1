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
$matchingPolicies = @(
    Get-SecureM365EnabledConditionalAccessPolicy |
    Where-Object {
        $riskLevels = @($_.conditions.userRiskLevels)
        $controls = @($_.grantControls.builtInControls)

        (Test-SecureM365CaTargetsAllUsers $_) -and
        (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $_ @approvedExclusions) -and
        (Test-SecureM365CaTargetsAllResources $_) -and
        (Test-SecureM365CaRequiresMfa $_) -and
        (Test-SecureM365CaUsesEveryTimeSignInFrequency $_) -and
        ($riskLevels -contains "high") -and
        ($controls -contains "passwordChange")
    }
)

[pscustomobject]@{
    Control          = "User risk policy"
    MatchingPolicies = @($matchingPolicies.displayName)
    Resolved         = $matchingPolicies.Count -gt 0
}

Test-SecureM365ScoreAction `
    -Title "Enable Microsoft Entra ID Identity Protection user risk policies" `
    -ControlName "UserRiskPolicy"
