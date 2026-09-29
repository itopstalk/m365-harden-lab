#Requires -Version 7.2
#Requires -Modules MicrosoftTeams

<#
.SYNOPSIS
Disables anonymous meeting join in Teams meeting policies.

.DESCRIPTION
Updates only the org-wide Global meeting policy. The lab intentionally does not
assess or configure custom meeting policies or their user/group assignments;
review those separately. Policy assignments are not changed. Review -WhatIf
output first because Global affects users who do not have a custom policy
assignment. The script verifies the exact Global identity before any write and
reads it back afterward.

.PARAMETER TeamsApplicationId
Use the dedicated Teams application instead of delegated authentication.
Requires exactly one of TeamsCertificateThumbprint or TeamsCertificatePath.

.PARAMETER TeamsCertificateThumbprint
Thumbprint in Cert:\CurrentUser\My for the Teams application certificate.

.PARAMETER TeamsCertificatePath
Path to a PFX outside this repository. Supply its runtime SecureString password
with TeamsCertificatePassword when needed.

.EXAMPLE
.\44-Disable-TeamsAnonymousMeetingJoin.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
.\44-Disable-TeamsAnonymousMeetingJoin.ps1 -TenantId $TenantId

#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $UseDeviceAuthentication,
    [guid] $TeamsApplicationId,
    [string] $TeamsCertificateThumbprint,
    [string] $TeamsCertificatePath,
    [securestring] $TeamsCertificatePassword
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Teams `
    -TenantId $TenantId `
    -UseDeviceAuthentication:$UseDeviceAuthentication `
    -ApplicationId $TeamsApplicationId `
    -CertificateThumbprint $TeamsCertificateThumbprint `
    -CertificatePath $TeamsCertificatePath `
    -CertificatePassword $TeamsCertificatePassword |
    Out-Null

$policy = Get-SecureM365TeamsMeetingPolicy
if ($policy.AllowAnonymousUsersToJoinMeeting -ne $false) {
    if ($PSCmdlet.ShouldProcess("Global", "Disable anonymous meeting join")) {
        try {
            Set-CsTeamsMeetingPolicy `
                -Identity Global `
                -AllowAnonymousUsersToJoinMeeting $false `
                -ErrorAction Stop
        }
        catch {
            $errorRecord = Get-SecureM365TeamsMeetingPolicyUpdateError -PolicyIdentity Global -ErrorRecord $_
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
}

Get-SecureM365TeamsMeetingPolicy |
    Select-Object Identity, AllowAnonymousUsersToJoinMeeting
