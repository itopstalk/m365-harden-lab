#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$authorizationPolicy = Invoke-MgGraphRequest `
    -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
    -ErrorAction Stop
$assignedPolicies = @(
    $authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
)
$userConsentPolicies = @(
    $assignedPolicies |
    Where-Object {
        $_ -match '(?i)^managePermissionGrantsForSelf\.' -or
        $_ -match '(?i)(^|\.)user-default'
    }
)

[pscustomobject]@{
    Control                = "User consent to applications"
    UserConsentPolicyCount = $userConsentPolicies.Count
    UserConsentPolicies    = $userConsentPolicies
    Resolved               = $userConsentPolicies.Count -eq 0
}

Test-SecureM365ScoreAction `
    -Title "Ensure user consent to apps accessing company data on their behalf is not allowed" `
    -ControlName "IntegratedApps"
