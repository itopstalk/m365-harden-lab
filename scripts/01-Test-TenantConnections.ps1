#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

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
        -UseDeviceAuthentication:$UseTeamsDeviceAuthentication

    $teamsConnection |
        Select-Object Account, Environment, Tenant, TenantId
}
