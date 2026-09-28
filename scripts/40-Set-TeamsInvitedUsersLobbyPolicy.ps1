#Requires -Version 7.2
#Requires -Modules MicrosoftTeams

<#
.SYNOPSIS
Sets Teams meeting lobby bypass to invited users.

.DESCRIPTION
Updates Global and every returned meeting policy by default, including predefined
and unused policies. Use -PolicyIdentity to restrict the targets, for example
-PolicyIdentity Global. Script 99 still audits all policies regardless of this selection.
The full target inventory is checked before the first update. Policy assignments
are not changed. Review -WhatIf output first; shared policy changes affect users
assigned to them. If Teams rejects an update, the script stops without rolling
back earlier changes. No unsupported or read-only policy is silently skipped.

.PARAMETER PolicyIdentity
Restrict updates to these policies. If omitted, all policies are targeted.
Cannot be combined with -AllPolicies.

.PARAMETER AllPolicies
Optional compatibility switch; all policies are already the default.
Use -PolicyIdentity Global to restrict updates to Global.

.EXAMPLE
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId

.EXAMPLE
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId -PolicyIdentity Global
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

    [switch] $UseDeviceAuthentication
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Teams `
    -TenantId $TenantId `
    -UseDeviceAuthentication:$UseDeviceAuthentication |
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
    if ($policy.AutoAdmittedUsers -ne "InvitedUsers") {
        if ($PSCmdlet.ShouldProcess($identity, "Set lobby bypass to invited users")) {
            Set-CsTeamsMeetingPolicy `
                -Identity $identity `
                -AutoAdmittedUsers "InvitedUsers" `
                -ErrorAction Stop
        }
    }

    Get-CsTeamsMeetingPolicy -Identity $identity -ErrorAction Stop |
        Select-Object Identity, AutoAdmittedUsers
}
