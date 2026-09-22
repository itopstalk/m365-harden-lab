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
    Where-Object { $_.AllowAnonymousUsersToJoinMeeting -ne $false }
)

[pscustomobject]@{
    Control              = "Block anonymous meeting join"
    NonCompliantPolicies = @($nonCompliantPolicies.Identity)
    Resolved             = $nonCompliantPolicies.Count -eq 0
}

Test-SecureM365ScoreAction `
    -Title "Restrict anonymous users from joining meetings" `
    -ControlName "meeting_restrictanonymousjoin_v1"
