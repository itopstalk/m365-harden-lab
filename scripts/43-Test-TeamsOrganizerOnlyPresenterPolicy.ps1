#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, MicrosoftTeams

<#
.SYNOPSIS
Tests the default presenter role on the Global Teams meeting policy.

.DESCRIPTION
Assesses only the org-wide Global meeting policy. Custom meeting policies and
their user/group assignments require separate review and are outside this check.
The script fails if Teams does not return exactly the Global policy.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $UseGraphDeviceCode,
    [switch] $UseTeamsDeviceAuthentication,
    [guid] $TeamsApplicationId,
    [string] $TeamsCertificateThumbprint,
    [string] $TeamsCertificatePath,
    [securestring] $TeamsCertificatePassword
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseGraphDeviceCode |
    Out-Null
Connect-SecureM365Teams `
    -TenantId $TenantId `
    -UseDeviceAuthentication:$UseTeamsDeviceAuthentication `
    -ApplicationId $TeamsApplicationId `
    -CertificateThumbprint $TeamsCertificateThumbprint `
    -CertificatePath $TeamsCertificatePath `
    -CertificatePassword $TeamsCertificatePassword |
    Out-Null

$policy = Get-SecureM365TeamsMeetingPolicy

[pscustomobject]@{
    Control        = "Limit default presenters"
    PolicyIdentity = $policy.Identity
    ActualValue    = $policy.DesignatedPresenterRoleMode
    ExpectedValue  = "OrganizerOnlyUserOverride"
    Resolved       = $policy.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride"
}

Test-SecureM365ScoreAction `
    -Title "Configure which users are allowed to present in Teams meetings" `
    -ControlName "meeting_designatedpresenter_v1"
