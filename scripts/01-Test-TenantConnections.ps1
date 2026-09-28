#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Connects to the intended tenant and validates the service access used by the scripts.

.DESCRIPTION
Validates the Microsoft Graph tenant, delegated authentication, and consented scopes.
With -IncludeTeams, also validates the Teams tenant and reads the Global meeting
policy to check access. A successful sign-in alone does not verify Teams permissions.
Run with -IncludeTeams before script 99 to detect Teams access failures early.

.PARAMETER IncludeTeams
Also connect to Microsoft Teams and verify meeting-policy read access. The Teams
account needs an active role permitted to read meeting policies, such as Teams
Communications Administrator. Graph consent does not grant Teams permissions.
If using PIM, activate the role and allow it to propagate, then disconnect Teams
and rerun this script to refresh the session.

.EXAMPLE
.\01-Test-TenantConnections.ps1 -TenantId $TenantId -IncludeTeams

.LINK
https://learn.microsoft.com/microsoftteams/using-admin-roles
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $IncludeTeams,
    [switch] $UseGraphDeviceCode,
    [switch] $UseTeamsDeviceAuthentication
)

$ErrorActionPreference = "Stop"
$commonModule = Join-Path $PSScriptRoot "SecureM365.Common.psm1"
Import-Module $commonModule -Force -ErrorAction Stop

$graphContext = Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseGraphDeviceCode

$graphContext |
    Select-Object Account, TenantId, AuthType, ContextScope, Scopes

if ($IncludeTeams) {
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        throw "MicrosoftTeams is not installed. Run 00-Install-PowerShellTools.ps1."
    }

    $teamsConnection = Connect-SecureM365Teams `
        -TenantId $TenantId `
        -ValidateMeetingPolicyAccess `
        -UseDeviceAuthentication:$UseTeamsDeviceAuthentication

    $teamsConnection |
        Select-Object Account, Environment, Tenant, TenantId
}
