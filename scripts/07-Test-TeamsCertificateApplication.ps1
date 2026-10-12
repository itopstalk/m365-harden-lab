#Requires -Version 7.2
#Requires -Modules MicrosoftTeams

<#
.SYNOPSIS
Tests the certificate application created by script 06.

.DESCRIPTION
Uses certificate-only Teams application authentication, validates the connected
tenant, and reads exactly the Global Teams meeting policy. A successful sign-in
alone is not considered a pass. No delegated Graph connection or interactive
administrator sign-in is requested.

For a thumbprint, first checks that exactly one certificate exists in
Cert:\CurrentUser\My, has a private key, and is currently valid. Script 06 creates
a non-exportable key: run under the same Windows user on the machine where that
certificate was created. Copying this script or a public certificate to another
machine does not transfer the private key.

Alternatively, use an approved PFX whose public certificate is already registered
on the application. The common module loads it ephemerally, checks for a private
key, and rejects paths inside the repository.

Returns a PASSED result only after the meeting-policy read succeeds. Failures
are terminating errors. This is a functional read-access check, not an audit of
exact role assignments, policy settings, or write permissions. It changes no
application, certificate, permission, or policy and leaves the Teams connection
available for subsequent commands.

Requires MicrosoftTeams and SecureM365.Common.psm1 alongside this script.
After role or consent changes, allow propagation and retry in a new PowerShell
process. Do not rerun script 06 to test an existing application.

.PARAMETER TenantId
The application's Microsoft Entra tenant GUID, as returned by script 06.

.PARAMETER ApplicationId
The ApplicationId (client ID) returned by script 06, not ApplicationObjectId
or ServicePrincipalObjectId.

.PARAMETER CertificateThumbprint
The CertificateThumbprint returned by script 06, in Cert:\CurrentUser\My.
Whitespace is removed before lookup.

.PARAMETER CertificatePath
Alternative path to an approved PFX outside this repository. The file must
contain the private key matching a certificate registered on the application.
The default non-exportable certificate from script 06 cannot be moved this way.

.PARAMETER CertificatePassword
Optional runtime SecureString for CertificatePath. Never store it in the script.

.EXAMPLE
.\07-Test-TeamsCertificateApplication.ps1 -TenantId $teamsApp.TenantId -ApplicationId $teamsApp.ApplicationId -CertificateThumbprint $teamsApp.CertificateThumbprint

.EXAMPLE
.\07-Test-TeamsCertificateApplication.ps1 -TenantId $TenantId -ApplicationId $TeamsApplicationId -CertificateThumbprint $TeamsCertificateThumbprint

.EXAMPLE
$pfxPassword = Read-Host "PFX password" -AsSecureString
.\07-Test-TeamsCertificateApplication.ps1 -TenantId $TenantId -ApplicationId $TeamsApplicationId -CertificatePath "C:\SecureM365Keys\teams.pfx" -CertificatePassword $pfxPassword

.LINK
https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
.LINK
https://learn.microsoft.com/powershell/module/microsoftteams/connect-microsoftteams
.LINK
https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmeetingpolicy
#>

[CmdletBinding(DefaultParameterSetName = "Thumbprint")]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $ApplicationId,

    [Parameter(Mandatory, ParameterSetName = "Thumbprint")]
    [ValidateNotNullOrEmpty()]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = "Pfx")]
    [ValidateNotNullOrEmpty()]
    [string] $CertificatePath,

    [Parameter(ParameterSetName = "Pfx")]
    [securestring] $CertificatePassword
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

if ($PSCmdlet.ParameterSetName -eq "Thumbprint") {
    $normalizedThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40,128}$') {
        throw "CertificateThumbprint must contain 40 through 128 hexadecimal characters."
    }
    $CertificateThumbprint = $normalizedThumbprint

    $certificates = @(
        Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop |
            Where-Object Thumbprint -eq $CertificateThumbprint
    )
    if ($certificates.Count -ne 1) {
        throw (
            "Expected exactly one certificate '$CertificateThumbprint' in Cert:\CurrentUser\My, but found $($certificates.Count). " +
            "Run as the Windows user on the machine where script 06 created the certificate. " +
            "Its non-exportable private key is not transferred by copying this script or a public certificate."
        )
    }
    $certificate = $certificates[0]
    if (-not $certificate.HasPrivateKey) {
        throw "Certificate '$CertificateThumbprint' has no private key available to the current Windows user. A public certificate alone cannot authenticate the application."
    }
    $now = Get-Date
    if ($certificate.NotBefore -gt $now) {
        throw "Certificate '$CertificateThumbprint' is not valid until $($certificate.NotBefore.ToString('o')). Check the system clock and certificate."
    }
    if ($certificate.NotAfter -le $now) {
        throw "Certificate '$CertificateThumbprint' expired at $($certificate.NotAfter.ToString('o')). Rotate the application's certificate before retrying."
    }
}

$connection = Connect-SecureM365Teams `
    -TenantId $TenantId `
    -ApplicationId $ApplicationId `
    -CertificateThumbprint $CertificateThumbprint `
    -CertificatePath $CertificatePath `
    -CertificatePassword $CertificatePassword `
    -ValidateMeetingPolicyAccess

[pscustomobject]@{
    Status                      = "PASSED"
    TenantId                    = [string] $connection.TenantId
    ApplicationId               = $ApplicationId.Guid
    AuthenticationType          = "AppOnly"
    CertificateSource           = if ($PSCmdlet.ParameterSetName -eq "Thumbprint") {
        "Cert:\CurrentUser\My\$CertificateThumbprint"
    }
    else {
        $CertificatePath
    }
    PolicyIdentity              = "Global"
    MeetingPolicyAccessVerified = $true
    CheckedAt                   = (Get-Date).ToUniversalTime().ToString("o")
}
