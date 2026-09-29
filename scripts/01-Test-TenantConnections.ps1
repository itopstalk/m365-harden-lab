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
Use script 05 before configuration scripts to check all required administrator
roles and Graph permissions and, with confirmation, assign missing lab roles.

In the GitHub Copilot App's embedded terminal, use -UseGraphBrowserPkce. It opens
Microsoft sign-in in the system browser and receives the authorization result on
a temporary localhost callback. Passwords are never accepted or stored by this
script. On first use, Microsoft may ask for delegated consent to the listed scopes.

.PARAMETER TenantId
Microsoft Entra tenant GUID. When omitted, the script prompts for it and rejects
blank, non-GUID, and all-zero values.

.PARAMETER UseGraphBrowserPkce
Use browser authorization-code authentication with PKCE, a random state and
nonce, and a temporary loopback callback. This is intended for embedded or
managed terminals where WAM and device-code prompts are not displayed.

.PARAMETER IncludeTeams
Also connect to Microsoft Teams and verify meeting-policy read access. The Teams
account needs an active role permitted to read meeting policies, such as Teams
Communications Administrator. Graph consent does not grant Teams permissions.
If using PIM, activate the role and allow it to propagate, then disconnect Teams
and rerun this script to refresh the session.

.PARAMETER TeamsApplicationId
Use the dedicated Teams application instead of delegated Teams authentication.
Requires exactly one of TeamsCertificateThumbprint or TeamsCertificatePath.

.PARAMETER TeamsCertificateThumbprint
Thumbprint in Cert:\CurrentUser\My for the Teams application certificate.

.PARAMETER TeamsCertificatePath
Path to a PFX outside this repository. Use only when the private key was
deliberately deployed to this Windows profile or machine.

.EXAMPLE
.\01-Test-TenantConnections.ps1 -TenantId $TenantId -IncludeTeams

.EXAMPLE
.\01-Test-TenantConnections.ps1 -UseGraphBrowserPkce

.LINK
https://learn.microsoft.com/microsoftteams/using-admin-roles
#>

[CmdletBinding()]
param(
    [string] $TenantId,

    [switch] $IncludeTeams,
    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce,
    [switch] $UseTeamsDeviceAuthentication,
    [guid] $TeamsApplicationId,
    [string] $TeamsCertificateThumbprint,
    [string] $TeamsCertificatePath,
    [securestring] $TeamsCertificatePassword
)

$ErrorActionPreference = "Stop"
$commonModule = Join-Path $PSScriptRoot "SecureM365.Common.psm1"
Import-Module $commonModule -Force -ErrorAction Stop
$TenantId = Resolve-SecureM365TenantId -TenantId $TenantId -PromptIfMissing

$graphContext = Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseGraphDeviceCode `
    -UseBrowserPkce:$UseGraphBrowserPkce

$graphContext |
    Select-Object Account, TenantId, AuthType, ContextScope, Scopes

if ($IncludeTeams) {
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        throw "MicrosoftTeams is not installed. Run 00-Install-PowerShellTools.ps1."
    }

    $teamsConnection = Connect-SecureM365Teams `
        -TenantId $TenantId `
        -ValidateMeetingPolicyAccess `
        -UseDeviceAuthentication:$UseTeamsDeviceAuthentication `
        -ApplicationId $TeamsApplicationId `
        -CertificateThumbprint $TeamsCertificateThumbprint `
        -CertificatePath $TeamsCertificatePath `
        -CertificatePassword $TeamsCertificatePassword

    $teamsConnection |
        Select-Object Account, Environment, Tenant, TenantId
}
