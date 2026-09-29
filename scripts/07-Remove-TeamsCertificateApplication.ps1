#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Revokes and removes the dedicated Teams certificate application.

.DESCRIPTION
Validates the target tenant, resolves exactly one application and service
principal by application ID, then removes its directory-role assignments,
application-role grants, service principal, and application registration.
Optionally removes one matching certificate from Cert:\CurrentUser\My.

Each destructive operation is protected by ShouldProcess with ConfirmImpact High.
The script is idempotent for already-removed cloud objects, but refuses ambiguous
matches and never removes a certificate unless explicitly requested.

.PARAMETER TenantId
The exact Microsoft Entra tenant GUID.

.PARAMETER ApplicationId
Client/application ID returned by script 06.

.PARAMETER CertificateThumbprint
Thumbprint of the local certificate. Required with RemoveLocalCertificate.

.PARAMETER RemoveLocalCertificate
Also remove the exact matching CurrentUser certificate after cloud revocation.

.EXAMPLE
.\07-Remove-TeamsCertificateApplication.ps1 -TenantId $TenantId -ApplicationId $ApplicationId -WhatIf

.EXAMPLE
.\07-Remove-TeamsCertificateApplication.ps1 -TenantId $TenantId -ApplicationId $ApplicationId -CertificateThumbprint $Thumbprint -RemoveLocalCertificate

.LINK
https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $ApplicationId,

    [string] $CertificateThumbprint,
    [switch] $RemoveLocalCertificate,
    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

if ($UseGraphDeviceCode -and $UseGraphBrowserPkce) {
    throw "UseGraphDeviceCode and UseGraphBrowserPkce cannot be combined."
}
if ($RemoveLocalCertificate -and [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
    throw "CertificateThumbprint is required with RemoveLocalCertificate."
}

$context = Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes @(
        "Application.ReadWrite.All"
        "AppRoleAssignment.ReadWrite.All"
        "Organization.Read.All"
        "RoleManagement.ReadWrite.Directory"
    ) `
    -UseDeviceCode:$UseGraphDeviceCode `
    -UseBrowserPkce:$UseGraphBrowserPkce
if ([string] $context.TenantId -ne $TenantId.Guid) {
    throw "Microsoft Graph connected to tenant '$($context.TenantId)' instead of '$($TenantId.Guid)'."
}
$organizations = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id"
)
if ($organizations.Count -ne 1 -or [string] $organizations[0].id -ne $TenantId.Guid) {
    throw "Microsoft Graph organization validation did not return exactly tenant '$($TenantId.Guid)'. No changes were made."
}

$applications = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId%20eq%20'$($ApplicationId.Guid)'&`$select=id,appId,displayName"
)
if ($applications.Count -gt 1) {
    throw "Multiple application objects unexpectedly matched application ID '$($ApplicationId.Guid)'. No changes were made."
}
$servicePrincipals = @(
    Get-SecureM365GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'$($ApplicationId.Guid)'&`$select=id,appId,displayName"
)
if ($servicePrincipals.Count -gt 1) {
    throw "Multiple service principals unexpectedly matched application ID '$($ApplicationId.Guid)'. No changes were made."
}

$servicePrincipal = $servicePrincipals | Select-Object -First 1
$directoryRoleAssignments = @()
$appRoleAssignments = @()
if ($null -ne $servicePrincipal) {
    $directoryRoleAssignments = @(
        Get-SecureM365GraphCollection `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId%20eq%20'$($servicePrincipal.id)'&`$select=id,principalId,roleDefinitionId,directoryScopeId"
    )
    $appRoleAssignments = @(
        Get-SecureM365GraphCollection `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments?`$select=id,principalId,resourceId,appRoleId"
    )
}

foreach ($assignment in $directoryRoleAssignments) {
    if ($PSCmdlet.ShouldProcess(
        "directory role assignment $($assignment.id)",
        "Remove from application $($ApplicationId.Guid)"
    )) {
        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$($assignment.id)" `
            -ErrorAction Stop
    }
}
foreach ($assignment in $appRoleAssignments) {
    if ($PSCmdlet.ShouldProcess(
        "application role assignment $($assignment.id)",
        "Remove from application $($ApplicationId.Guid)"
    )) {
        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments/$($assignment.id)" `
            -ErrorAction Stop
    }
}
if ($null -ne $servicePrincipal -and $PSCmdlet.ShouldProcess(
    "$($servicePrincipal.displayName) service principal ($($servicePrincipal.id))",
    "Delete"
)) {
    Invoke-MgGraphRequest `
        -Method DELETE `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)" `
        -ErrorAction Stop
}
$application = $applications | Select-Object -First 1
if ($null -ne $application -and $PSCmdlet.ShouldProcess(
    "$($application.displayName) application ($($application.id))",
    "Delete"
)) {
    Invoke-MgGraphRequest `
        -Method DELETE `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($application.id)" `
        -ErrorAction Stop
}

$certificateRemoved = $false
if ($RemoveLocalCertificate) {
    $normalizedThumbprint = $CertificateThumbprint -replace '\s', ''
    if ($normalizedThumbprint -notmatch '^[0-9A-Fa-f]{40,128}$') {
        throw "CertificateThumbprint must contain only hexadecimal characters."
    }
    $certificates = @(
        Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop |
            Where-Object Thumbprint -eq $normalizedThumbprint
    )
    if ($certificates.Count -gt 1) {
        throw "Multiple CurrentUser certificates unexpectedly matched thumbprint '$normalizedThumbprint'. No certificate was removed."
    }
    if ($certificates.Count -eq 1 -and $PSCmdlet.ShouldProcess(
        "Cert:\CurrentUser\My\$normalizedThumbprint",
        "Remove local private certificate"
    )) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$normalizedThumbprint" -ErrorAction Stop
        $certificateRemoved = $true
    }
}

[pscustomobject]@{
    TenantId = $TenantId.Guid
    ApplicationId = $ApplicationId.Guid
    ApplicationFound = $applications.Count -eq 1
    ServicePrincipalFound = $servicePrincipals.Count -eq 1
    DirectoryRoleAssignmentsFound = $directoryRoleAssignments.Count
    AppRoleAssignmentsFound = $appRoleAssignments.Count
    LocalCertificateRemoved = $certificateRemoved
}
