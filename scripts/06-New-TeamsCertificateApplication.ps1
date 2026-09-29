#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, MicrosoftTeams

<#
.SYNOPSIS
Creates a dedicated certificate-authenticated application for Teams meeting policies.

.DESCRIPTION
Creates a non-exportable RSA certificate in Cert:\CurrentUser\My, a single-tenant
Entra application and service principal, and grants only Microsoft Graph
Organization.Read.All plus the Teams Communications Administrator directory role.
It uploads only the public certificate. Client secrets are never created.

The script refuses application display-name and local certificate-subject
collisions rather than changing an existing identity. Run the teardown script
before recreating or rotating this lab identity. A single high-impact confirmation
covers all planned writes. If a later write fails, the error lists created object
IDs and the exact teardown command; completed writes are not silently rolled back.

Application setup requires delegated Application.ReadWrite.All,
AppRoleAssignment.ReadWrite.All, Organization.Read.All, and
RoleManagement.ReadWrite.Directory. These operator permissions are not assigned
to the new application. The application itself receives only Organization.Read.All
and Teams Communications Administrator.
Microsoft explicitly warns not to configure Skype and Teams Tenant Admin API
permission for Teams PowerShell application authentication.

.PARAMETER TenantId
The exact Microsoft Entra tenant GUID. The signed-in Graph tenant and organization
record must both match.

.PARAMETER DisplayName
Unique display name for the dedicated application.

.PARAMETER CertificateSubject
Unique subject for the CurrentUser certificate. The default is scoped to this lab.

.PARAMETER CertificateValidityMonths
Certificate validity, from 1 through 24 months. The default is 12.

.PARAMETER UseGraphDeviceCode
Use delegated Graph device-code authentication for setup.

.PARAMETER UseGraphBrowserPkce
Use the repository browser-PKCE Graph authentication flow for setup.

.EXAMPLE
.\06-New-TeamsCertificateApplication.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
$result = .\06-New-TeamsCertificateApplication.ps1 -TenantId $TenantId

.LINK
https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
.LINK
https://learn.microsoft.com/powershell/module/microsoftteams/connect-microsoftteams
.LINK
https://learn.microsoft.com/microsoftteams/using-admin-roles
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,

    [ValidateNotNullOrEmpty()]
    [string] $DisplayName = "SecureM365 Teams Meeting Policy Automation",

    [ValidatePattern('^CN=[^,=]+$')]
    [string] $CertificateSubject = "CN=SecureM365 Teams Meeting Policy Automation",

    [ValidateRange(1, 24)]
    [int] $CertificateValidityMonths = 12,

    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

if ($UseGraphDeviceCode -and $UseGraphBrowserPkce) {
    throw "UseGraphDeviceCode and UseGraphBrowserPkce cannot be combined."
}

$setupScopes = @(
    "Application.ReadWrite.All"
    "AppRoleAssignment.ReadWrite.All"
    "Organization.Read.All"
    "RoleManagement.ReadWrite.Directory"
)
$context = Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes $setupScopes `
    -UseDeviceCode:$UseGraphDeviceCode `
    -UseBrowserPkce:$UseGraphBrowserPkce
if ([string] $context.TenantId -ne $TenantId.Guid) {
    throw "Microsoft Graph connected to tenant '$($context.TenantId)' instead of '$($TenantId.Guid)'."
}

$organizations = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName"
)
if ($organizations.Count -ne 1 -or [string] $organizations[0].id -ne $TenantId.Guid) {
    throw "Microsoft Graph organization validation did not return exactly tenant '$($TenantId.Guid)'. No changes were made."
}

$escapedDisplayName = $DisplayName.Replace("'", "''")
$applications = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName%20eq%20'$([uri]::EscapeDataString($escapedDisplayName))'&`$select=id,appId,displayName"
)
if ($applications.Count -gt 0) {
    throw "An Entra application named '$DisplayName' already exists. This script refuses collisions; inspect or remove it explicitly before retrying."
}

$certificates = @(
    Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop |
        Where-Object Subject -eq $CertificateSubject
)
if ($certificates.Count -gt 0) {
    throw "A CurrentUser certificate with subject '$CertificateSubject' already exists. This script refuses collisions; inspect or remove it explicitly before retrying."
}

$graphServicePrincipals = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'&`$select=id,appId,appRoles"
)
if ($graphServicePrincipals.Count -ne 1) {
    throw "Could not uniquely resolve the Microsoft Graph service principal. No changes were made."
}
$organizationReadRole = @(
    $graphServicePrincipals[0].appRoles |
        Where-Object { $_.value -eq "Organization.Read.All" -and $_.allowedMemberTypes -contains "Application" }
)
if ($organizationReadRole.Count -ne 1) {
    throw "Could not uniquely resolve the Microsoft Graph Organization.Read.All application role. No changes were made."
}

$teamsRoleDefinitions = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=templateId%20eq%20'baf37b3a-610e-45da-9e62-d9d1e5e8914b'&`$select=id,templateId,displayName,isBuiltIn"
)
if (
    $teamsRoleDefinitions.Count -ne 1 -or
    $teamsRoleDefinitions[0].displayName -ne "Teams Communications Administrator" -or
    $teamsRoleDefinitions[0].isBuiltIn -ne $true
) {
    throw "Could not uniquely resolve the built-in Teams Communications Administrator role. No changes were made."
}

$plan = [pscustomobject]@{
    TenantId                  = $TenantId.Guid
    TenantDisplayName         = [string] $organizations[0].displayName
    ApplicationDisplayName    = $DisplayName
    CertificateSubject        = $CertificateSubject
    CertificateStore          = "Cert:\CurrentUser\My"
    CertificateExportable     = $false
    GraphApplicationPermission = "Organization.Read.All"
    DirectoryRole             = "Teams Communications Administrator"
}
if (-not $PSCmdlet.ShouldProcess(
    "$DisplayName in tenant $($TenantId.Guid)",
    "Create the local non-exportable certificate, application, service principal, API grant, and directory-role assignment"
)) {
    return $plan
}

$certificate = $null
$application = $null
$servicePrincipal = $null
$appRoleAssignment = $null
$directoryRoleAssignment = $null
try {
    $certificate = New-SelfSignedCertificate `
        -Subject $CertificateSubject `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -KeySpec Signature `
        -NotAfter (Get-Date).AddMonths($CertificateValidityMonths) `
        -ErrorAction Stop
    if (-not $certificate.HasPrivateKey) {
        throw "The generated certificate does not expose its private key to the current Windows user."
    }

    $applicationBody = @{
        displayName = $DisplayName
        signInAudience = "AzureADMyOrg"
        keyCredentials = @(
            @{
                type = "AsymmetricX509Cert"
                usage = "Verify"
                keyId = [guid]::NewGuid().Guid
                displayName = $CertificateSubject
                startDateTime = $certificate.NotBefore.ToUniversalTime().ToString("o")
                endDateTime = $certificate.NotAfter.ToUniversalTime().ToString("o")
                key = [Convert]::ToBase64String($certificate.RawData)
            }
        )
        requiredResourceAccess = @(
            @{
                resourceAppId = "00000003-0000-0000-c000-000000000000"
                resourceAccess = @(
                    @{
                        id = [string] $organizationReadRole[0].id
                        type = "Role"
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 8
    $application = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/applications" `
        -Body $applicationBody `
        -ContentType "application/json" `
        -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string] $application.id) -or
        [string]::IsNullOrWhiteSpace([string] $application.appId)) {
        throw "Microsoft Graph returned an incomplete application object."
    }

    $servicePrincipal = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
        -Body (@{ appId = [string] $application.appId } | ConvertTo-Json) `
        -ContentType "application/json" `
        -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string] $servicePrincipal.id)) {
        throw "Microsoft Graph returned an incomplete service principal object."
    }

    $appRoleAssignment = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments" `
        -Body (@{
            principalId = [string] $servicePrincipal.id
            resourceId = [string] $graphServicePrincipals[0].id
            appRoleId = [string] $organizationReadRole[0].id
        } | ConvertTo-Json) `
        -ContentType "application/json" `
        -ErrorAction Stop

    $directoryRoleAssignment = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
        -Body (@{
            principalId = [string] $servicePrincipal.id
            roleDefinitionId = [string] $teamsRoleDefinitions[0].id
            directoryScopeId = "/"
        } | ConvertTo-Json) `
        -ContentType "application/json" `
        -ErrorAction Stop

    $connectionError = $null
    foreach ($attempt in 1..6) {
        try {
            Connect-SecureM365Teams `
                -TenantId $TenantId `
                -ApplicationId ([guid] $application.appId) `
                -CertificateThumbprint $certificate.Thumbprint `
                -ValidateMeetingPolicyAccess |
                Out-Null
            $connectionError = $null
            break
        }
        catch {
            $connectionError = $_
            Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
            if ($attempt -lt 6) {
                Write-Warning "Teams application access is not available yet; waiting 10 seconds for role and consent propagation (attempt $attempt of 6)."
                Start-Sleep -Seconds 10
            }
        }
    }
    if ($null -ne $connectionError) {
        throw [InvalidOperationException]::new(
            "The application and grants were created, but Teams meeting-policy access could not be verified after six attempts. " +
            "Allow additional role and consent propagation time, then validate with script 01 before deciding whether to revoke. " +
            "Last error: $($connectionError.Exception.Message)",
            $connectionError.Exception
        )
    }

    [pscustomobject]@{
        TenantId                  = $TenantId.Guid
        ApplicationDisplayName    = $DisplayName
        ApplicationId             = [string] $application.appId
        ApplicationObjectId       = [string] $application.id
        ServicePrincipalObjectId  = [string] $servicePrincipal.id
        CertificateThumbprint     = [string] $certificate.Thumbprint
        CertificateSubject        = $CertificateSubject
        CertificateNotAfter       = $certificate.NotAfter
        GraphApplicationPermission = "Organization.Read.All"
        AppRoleAssignmentId       = [string] $appRoleAssignment.id
        DirectoryRole             = "Teams Communications Administrator"
        DirectoryRoleAssignmentId = [string] $directoryRoleAssignment.id
        MeetingPolicyAccessVerified = $true
    }
}
catch {
    $partialState = @(
        "CertificateThumbprint=$([string] $certificate.Thumbprint)"
        "ApplicationId=$([string] $application.appId)"
        "ApplicationObjectId=$([string] $application.id)"
        "ServicePrincipalObjectId=$([string] $servicePrincipal.id)"
        "AppRoleAssignmentId=$([string] $appRoleAssignment.id)"
        "DirectoryRoleAssignmentId=$([string] $directoryRoleAssignment.id)"
    ) -join "; "
    $teardown = if (-not [string]::IsNullOrWhiteSpace([string] $application.appId)) {
        ".\07-Remove-TeamsCertificateApplication.ps1 -TenantId '$($TenantId.Guid)' -ApplicationId '$($application.appId)' -CertificateThumbprint '$([string] $certificate.Thumbprint)' -RemoveLocalCertificate"
    }
    else {
        "Remove the local certificate '$([string] $certificate.Thumbprint)' from Cert:\CurrentUser\My after verifying it belongs to this failed setup."
    }
    throw [InvalidOperationException]::new(
        "Teams certificate application setup failed. Completed changes were not rolled back. $partialState. " +
        "After reviewing the IDs, revoke partial state with: $teardown. Original error: $($_.Exception.Message)",
        $_.Exception
    )
}
