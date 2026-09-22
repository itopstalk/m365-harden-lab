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
    -AdditionalScopes "Policy.ReadWrite.SecurityDefaults" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

if (Get-SecureM365SecurityDefaultsEnabled) {
    [pscustomobject]@{
        TenantId = $TenantId.Guid
        Control  = "Security defaults"
        Enabled  = $true
        Changed  = $false
    }
    return
}

$changed = $false
if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Enable Microsoft Entra security defaults")) {
    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy `
        -BodyParameter @{ isEnabled = $true } `
        -ErrorAction Stop
    $changed = $true
}

[pscustomobject]@{
    TenantId = $TenantId.Guid
    Control  = "Security defaults"
    Enabled  = Get-SecureM365SecurityDefaultsEnabled
    Changed  = $changed
}
