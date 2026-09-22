#Requires -Version 7.2
#Requires -Modules MicrosoftTeams

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [string[]] $PolicyIdentity = @("Global"),
    [switch] $UseDeviceAuthentication
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Teams `
    -TenantId $TenantId `
    -UseDeviceAuthentication:$UseDeviceAuthentication |
    Out-Null

foreach ($identity in $PolicyIdentity) {
    $policy = Get-CsTeamsMeetingPolicy -Identity $identity -ErrorAction Stop
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
