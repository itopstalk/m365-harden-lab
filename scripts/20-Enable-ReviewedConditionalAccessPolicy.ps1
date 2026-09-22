#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [guid] $ConditionalAccessPolicyId,

    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Policy.ReadWrite.ConditionalAccess" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$policy = Get-MgIdentityConditionalAccessPolicy `
    -ConditionalAccessPolicyId $ConditionalAccessPolicyId.Guid `
    -ErrorAction Stop

if ($policy.State -eq "enabled") {
    $policy | Select-Object Id, DisplayName, State
    return
}
if ($policy.State -ne "enabledForReportingButNotEnforced") {
    throw "Policy '$($policy.DisplayName)' is '$($policy.State)', not report-only. Review it before enabling."
}

if ($PSCmdlet.ShouldProcess($policy.DisplayName, "Enable Conditional Access policy")) {
    Update-MgIdentityConditionalAccessPolicy `
        -ConditionalAccessPolicyId $policy.Id `
        -BodyParameter @{ state = "enabled" } `
        -ErrorAction Stop
}

Get-MgIdentityConditionalAccessPolicy `
    -ConditionalAccessPolicyId $policy.Id `
    -ErrorAction Stop |
    Select-Object Id, DisplayName, State
