#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Policy.ReadWrite.Authorization" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$authorizationPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
$assignedPolicies = @(
    $authorizationPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
)
$preservedPolicies = @(
    $assignedPolicies |
    Where-Object {
        $_ -notmatch '(?i)^managePermissionGrantsForSelf\.' -and
        $_ -notmatch '(?i)(^|\.)user-default'
    }
)
$removedPolicies = @(
    $assignedPolicies |
    Where-Object { $_ -notin $preservedPolicies }
)

if ($removedPolicies.Count -eq 0) {
    [pscustomobject]@{
        TenantId       = $TenantId.Guid
        RemovedPolicies = @()
        Changed        = $false
    }
    return
}

$changed = $false
if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Remove ordinary-user application consent policies")) {
    Update-MgPolicyAuthorizationPolicy `
        -BodyParameter @{
            defaultUserRolePermissions = @{
                permissionGrantPoliciesAssigned = $preservedPolicies
            }
        } `
        -ErrorAction Stop
    $changed = $true
}

[pscustomobject]@{
    TenantId        = $TenantId.Guid
    RemovedPolicies = $removedPolicies
    Changed         = $changed
}
