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
    Where-Object {
        $_.DesignatedPresenterRoleMode -ne "OrganizerOnlyUserOverride"
    }
)

[pscustomobject]@{
    Control              = "Limit default presenters"
    NonCompliantPolicies = @($nonCompliantPolicies.Identity)
    Resolved             = $nonCompliantPolicies.Count -eq 0
}

Test-SecureM365ScoreAction `
    -Title "Configure which users are allowed to present in Teams meetings" `
    -ControlName "meeting_designatedpresenter_v1"
