#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $UseGraphDeviceCode,
    [switch] $UseTeamsDeviceAuthentication
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseGraphDeviceCode |
    Out-Null
Connect-SecureM365Teams `
    -TenantId $TenantId `
    -UseDeviceAuthentication:$UseTeamsDeviceAuthentication |
    Out-Null

$nonCompliantPolicies = @(
    Get-CsTeamsMeetingPolicy -ErrorAction Stop |
    Where-Object { $_.AutoAdmittedUsers -ne "InvitedUsers" }
)

[pscustomobject]@{
    Control              = "Only invited users bypass the lobby"
    NonCompliantPolicies = @($nonCompliantPolicies.Identity)
    Resolved             = $nonCompliantPolicies.Count -eq 0
}

Test-SecureM365ScoreAction `
    -Title "Only invited users should be automatically admitted to Teams meetings" `
    -ControlName "meeting_autoadmitusers_v1"
