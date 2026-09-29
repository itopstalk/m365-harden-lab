#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Tests the queryable Microsoft Entra settings used by Microsoft 365 Baseline Security Mode.

.DESCRIPTION
Uses read-only Microsoft Graph v1.0 requests to validate four underlying tenant
controls. This script does not read the Baseline Security Mode UI toggle or its
impact-report state because Microsoft documents no API for that surface.

Missing permissions, failed reads, empty/malformed responses, and configurations
that cannot be proven from the returned data are reported as UNKNOWN. Disabled
and report-only Conditional Access policies do not count as enabled.

.PARAMETER TenantId
The intended Microsoft Entra tenant GUID.

.PARAMETER UseGraphDeviceCode
Use device-code authentication for Microsoft Graph.

.PARAMETER UseGraphBrowserPkce
Use browser authorization code authentication with PKCE and the repository's
temporary localhost callback.

.EXAMPLE
.\62-Test-BaselineAuthenticationAndApps.ps1 -TenantId $TenantId -UseGraphBrowserPkce

.LINK
https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide
.LINK
https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies
.LINK
https://learn.microsoft.com/en-us/graph/api/tenantappmanagementpolicy-get
.LINK
https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,
    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

$catalog = @{}
Get-SecureM365BaselineCatalog |
    Where-Object Automation -eq "Graph" |
    ForEach-Object { $catalog[$_.SettingId] = $_ }
$checkedAt = [datetimeoffset]::UtcNow

function New-UnknownResult {
    param([Parameter(Mandatory)][string] $SettingId, [Parameter(Mandatory)][string] $Evidence)
    New-SecureM365BaselineResult -CatalogEntry $catalog[$SettingId] -Status UNKNOWN `
        -ActualValue $null -Evidence $Evidence -CheckedAt $checkedAt
}

function Test-AllValuesPresent {
    param([object[]] $Required, [object[]] $Actual)
    @($Required | Where-Object { $_ -notin @($Actual) }).Count -eq 0
}

try {
    Connect-SecureM365Graph -TenantId $TenantId -AdditionalScopes @("Policy.Read.All") `
        -UseDeviceCode:$UseGraphDeviceCode -UseBrowserPkce:$UseGraphBrowserPkce | Out-Null
}
catch {
    $message = "Microsoft Graph connection failed: $($_.Exception.Message)"
    return @($catalog.Keys | Sort-Object | ForEach-Object { New-UnknownResult $_ $message })
}

$conditionalAccessPolicies = $null
$conditionalAccessError = $null
try {
    $conditionalAccessPolicies = @(
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
            -Headers @{ Prefer = "include-unknown-enum-members" }
    )
    foreach ($policy in $conditionalAccessPolicies) {
        if (
            [string]::IsNullOrWhiteSpace([string] $policy.id) -or
            [string]::IsNullOrWhiteSpace([string] $policy.displayName) -or
            [string]::IsNullOrWhiteSpace([string] $policy.state) -or
            $null -eq $policy.conditions -or $null -eq $policy.grantControls
        ) {
            throw "Conditional Access returned an incomplete policy object."
        }
    }
}
catch {
    $conditionalAccessError = $_.Exception.Message
}

$requiredAdminRoleTemplateIds = @(
    "62e90394-69f5-4237-9190-012177145e10" # Global Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea10c" # Application Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" # Authentication Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe" # Billing Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7" # Cloud Application Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" # Conditional Access Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de" # Exchange Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" # Helpdesk Administrator
    "7495fdc4-34c4-4d15-a289-98788ce399fd" # Password Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" # Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814" # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d" # Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" # SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1" # User Administrator
)

if ($conditionalAccessError) {
    New-UnknownResult "AUTH-001" "Conditional Access read failed: $conditionalAccessError"
    New-UnknownResult "AUTH-002" "Conditional Access read failed: $conditionalAccessError"
}
else {
    $phishingPolicies = @(
        $conditionalAccessPolicies | Where-Object {
            $_.state -eq "enabled" -and
            $_.grantControls.authenticationStrength.id -eq "00000000-0000-0000-0000-000000000004" -and
            (Test-AllValuesPresent -Required $requiredAdminRoleTemplateIds -Actual @($_.conditions.users.includeRoles)) -and
            (
                @($_.conditions.applications.includeApplications) -contains "All" -or
                @($_.conditions.applications.includeApplications) -contains "MicrosoftAdminPortals"
            )
        }
    )
    if ($phishingPolicies.Count -gt 0) {
        New-SecureM365BaselineResult -CatalogEntry $catalog["AUTH-001"] -Status ENABLED `
            -Resolved $true -ActualValue @($phishingPolicies.displayName) `
            -Evidence "Enabled policy coverage found: $($phishingPolicies.displayName -join ', ')." `
            -CheckedAt $checkedAt
    }
    else {
        $candidateNames = @(
            $conditionalAccessPolicies |
                Where-Object { $_.grantControls.authenticationStrength.id -eq "00000000-0000-0000-0000-000000000004" } |
                ForEach-Object displayName
        )
        New-SecureM365BaselineResult -CatalogEntry $catalog["AUTH-001"] -Status DISABLED `
            -Resolved $false -ActualValue $candidateNames `
            -Evidence "No enabled policy simultaneously covered every documented privileged role, Microsoft Admin Portals, and the phishing-resistant MFA authentication strength. Matching-strength candidates: $($candidateNames -join ', ')." `
            -CheckedAt $checkedAt
    }

    $legacyPolicies = @(
        $conditionalAccessPolicies | Where-Object {
            $clients = @($_.conditions.clientAppTypes)
            $_.state -eq "enabled" -and
            @($_.conditions.users.includeUsers) -contains "All" -and
            @($_.conditions.applications.includeApplications) -contains "All" -and
            $clients -contains "exchangeActiveSync" -and
            $clients -contains "other" -and
            @($_.grantControls.builtInControls) -contains "block"
        }
    )
    if ($legacyPolicies.Count -gt 0) {
        New-SecureM365BaselineResult -CatalogEntry $catalog["AUTH-002"] -Status ENABLED `
            -Resolved $true -ActualValue @($legacyPolicies.displayName) `
            -Evidence "Enabled all-user/all-resource legacy-client block found: $($legacyPolicies.displayName -join ', ')." `
            -CheckedAt $checkedAt
    }
    else {
        $candidateNames = @(
            $conditionalAccessPolicies |
                Where-Object {
                    @($_.conditions.clientAppTypes) -contains "exchangeActiveSync" -or
                    @($_.conditions.clientAppTypes) -contains "other"
                } |
                ForEach-Object displayName
        )
        New-SecureM365BaselineResult -CatalogEntry $catalog["AUTH-002"] -Status DISABLED `
            -Resolved $false -ActualValue $candidateNames `
            -Evidence "No enabled policy blocked both documented legacy client types for all users and all resources. Candidates: $($candidateNames -join ', ')." `
            -CheckedAt $checkedAt
    }
}

try {
    $appPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' `
        -ErrorAction Stop
    if (
        $null -eq $appPolicy.applicationRestrictions -or
        $null -eq $appPolicy.servicePrincipalRestrictions -or
        $null -eq $appPolicy.applicationRestrictions.passwordCredentials -or
        $null -eq $appPolicy.servicePrincipalRestrictions.passwordCredentials
    ) {
        throw "The default app management policy omitted password-credential restrictions."
    }
    $applicationRestriction = @(
        $appPolicy.applicationRestrictions.passwordCredentials |
            Where-Object restrictionType -eq "passwordAddition"
    )
    $servicePrincipalRestriction = @(
        $appPolicy.servicePrincipalRestrictions.passwordCredentials |
            Where-Object restrictionType -eq "passwordAddition"
    )
    if ($applicationRestriction.Count -ne 1 -or $servicePrincipalRestriction.Count -ne 1) {
        throw "Expected exactly one passwordAddition restriction for applications and service principals."
    }
    $enabled =
        $applicationRestriction[0].state -eq "enabled" -and
        $servicePrincipalRestriction[0].state -eq "enabled"
    New-SecureM365BaselineResult -CatalogEntry $catalog["ENTRA-APP-001"] `
        -Status $(if ($enabled) { "ENABLED" } else { "DISABLED" }) -Resolved $enabled `
        -ActualValue @{
            Applications = $applicationRestriction[0].state
            ServicePrincipals = $servicePrincipalRestriction[0].state
        } -Evidence "Read Microsoft Graph defaultAppManagementPolicy passwordAddition restrictions." `
        -CheckedAt $checkedAt
}
catch {
    New-UnknownResult "ENTRA-APP-001" "Default app management policy read failed or was malformed: $($_.Exception.Message)"
}

try {
    $authorizationPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
        -ErrorAction Stop
    $assigned = $authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
    if ($null -eq $assigned) {
        throw "The authorization policy omitted permissionGrantPoliciesAssigned."
    }
    $assigned = @($assigned)
    $expected = "managePermissionGrantsForSelf.microsoft-user-default-low"
    $enabled = $assigned.Count -eq 1 -and $assigned[0] -eq $expected
    New-SecureM365BaselineResult -CatalogEntry $catalog["ENTRA-APP-002"] `
        -Status $(if ($enabled) { "ENABLED" } else { "DISABLED" }) -Resolved $enabled `
        -ActualValue $assigned `
        -Evidence "Default-user permission grant policy assignments: $($assigned -join ', ')." `
        -CheckedAt $checkedAt
}
catch {
    New-UnknownResult "ENTRA-APP-002" "Authorization policy read failed or was malformed: $($_.Exception.Message)"
}
