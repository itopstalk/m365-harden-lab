#Requires -Version 7.2
#Requires -Modules MicrosoftTeams

<#
.SYNOPSIS
Sets the Teams meeting default presenter role to organizers only.

.DESCRIPTION
Attempts to update Global and every returned meeting policy by default, including
predefined and unused policies. Only Global and tenant-created custom policies
are editable; Microsoft-managed presets are read-only. Use -PolicyIdentity Global
or explicitly select tenant-created policies to avoid targeting those presets.
Script 99 still audits all policies, including read-only and unused presets.
The full target inventory is checked before the first update. Policy assignments
are not changed. Review -WhatIf output first; shared policy changes affect users
assigned to them. If Teams rejects an update, the script stops without rolling
back earlier changes. The first-party read-only rejection includes guidance;
no policy is skipped or retried, and other errors retain their original details.
WhatIf previews targets but cannot verify whether Teams will allow an update.

.PARAMETER PolicyIdentity
Restrict updates to these policies. If omitted, all policies are targeted.
Cannot be combined with -AllPolicies.

.PARAMETER AllPolicies
Optional compatibility switch; all policies are already the default.
Use -PolicyIdentity Global to restrict updates to Global.

.PARAMETER TeamsApplicationId
Use the dedicated Teams application instead of delegated authentication.
Requires exactly one of TeamsCertificateThumbprint or TeamsCertificatePath.

.PARAMETER TeamsCertificateThumbprint
Thumbprint in Cert:\CurrentUser\My for the Teams application certificate.

.PARAMETER TeamsCertificatePath
Path to a PFX outside this repository. Supply its runtime SecureString password
with TeamsCertificatePassword when needed.

.EXAMPLE
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId

.EXAMPLE
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId -PolicyIdentity Global
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High", DefaultParameterSetName = "AllPolicies")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory, ParameterSetName = "SelectedPolicies")]
    [ValidateNotNullOrEmpty()]
    [string[]] $PolicyIdentity,

    [Parameter(ParameterSetName = "AllPolicies")]
    [switch] $AllPolicies,

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

$selection = if ($PSCmdlet.ParameterSetName -eq "SelectedPolicies") {
    @{ PolicyIdentity = $PolicyIdentity }
}
else {
    @{ AllPolicies = $true }
}
$policies = @(Get-SecureM365TeamsMeetingPolicy @selection)
foreach ($policy in $policies) {
    $identity = [string] $policy.Identity
    if ($policy.DesignatedPresenterRoleMode -ne "OrganizerOnlyUserOverride") {
        if ($PSCmdlet.ShouldProcess($identity, "Set the default presenter role to organizers only")) {
            try {
                Set-CsTeamsMeetingPolicy `
                    -Identity $identity `
                    -DesignatedPresenterRoleMode "OrganizerOnlyUserOverride" `
                    -ErrorAction Stop
            }
            catch {
                $errorRecord = Get-SecureM365TeamsMeetingPolicyUpdateError -PolicyIdentity $identity -ErrorRecord $_
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }
    }

    Get-CsTeamsMeetingPolicy -Identity $identity -ErrorAction Stop |
        Select-Object Identity, DesignatedPresenterRoleMode
}
