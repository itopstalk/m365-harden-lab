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
        $riskLevels = @($_.conditions.signInRiskLevels)

        (Test-SecureM365CaTargetsAllUsers $_) -and
        (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $_ @approvedExclusions) -and
        (Test-SecureM365CaTargetsAllResources $_) -and
        (Test-SecureM365CaRequiresMfa $_) -and
        (Test-SecureM365CaUsesEveryTimeSignInFrequency $_) -and
        ($riskLevels -contains "medium") -and
        ($riskLevels -contains "high")
    }
)

[pscustomobject]@{
    Control          = "Sign-in risk policy"
    MatchingPolicies = @($matchingPolicies.displayName)
    Resolved         = $matchingPolicies.Count -gt 0
}

Test-SecureM365ScoreAction `
    -Title "Enable Microsoft Entra ID Identity Protection sign-in risk policies" `
    -ControlName "SigninRiskPolicy"
