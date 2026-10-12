#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Checks whether an administrator MFA policy is present and enabled.

.DESCRIPTION
Resolved is true when Security Defaults is enabled or an enabled Conditional
Access policy requires MFA and directly targets directory roles or all users.
PolicyFound and EnabledPolicyFound describe actual Conditional Access policies,
not the presence or score of a Microsoft Secure Score control.

Reports matching policy IDs, names, states, and exclusions. Complete coverage of
script 10's administrator-role baseline is assessed separately as CoverageVerified.
Unapproved exclusions, narrower conditions, and incomplete user registration do
not change the enabled-policy result. This is a configuration check, not proof
that every administrator or sign-in is protected.

MFA registration is advisory and can lag by up to 36 hours. Registration-report
or role-inventory failures are reported without hiding a verified enabled policy.
No Secure Score snapshot is consulted and no tenant settings are changed.

.PARAMETER TenantId
The Microsoft Entra tenant GUID.

.PARAMETER ApprovedExcludedUserId
Reviewed user exclusions, such as the emergency account IDs supplied to script 10.
Used only for the separate coverage advisory; not required to find the policy.

.PARAMETER ApprovedExcludedGroupId
Reviewed group exclusions for the coverage advisory.

.PARAMETER ApprovedExcludedRoleId
Reviewed role-template exclusions for the coverage advisory.

.EXAMPLE
.\11-Test-AdminMfa.ps1 -TenantId $TenantId

.EXAMPLE
.\11-Test-AdminMfa.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

.LINK
https://learn.microsoft.com/entra/identity/conditional-access/policy-old-require-mfa-admin
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [guid[]] $ApprovedExcludedUserId = @(),
    [guid[]] $ApprovedExcludedGroupId = @(),
    [guid[]] $ApprovedExcludedRoleId = @(),
    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$approvedExclusions = @{
    ApprovedExcludedUserIds = @($ApprovedExcludedUserId | ForEach-Object { $_.Guid })
    ApprovedExcludedGroupIds = @($ApprovedExcludedGroupId | ForEach-Object { $_.Guid })
    ApprovedExcludedRoleIds = @($ApprovedExcludedRoleId | ForEach-Object { $_.Guid })
}
$policies = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
)
$securityDefaultsEnabled = Get-SecureM365SecurityDefaultsEnabled

$adminRoleNames = @(
    "Global Administrator"
    "Application Administrator"
    "Authentication Administrator"
    "Authentication Policy Administrator"
    "Billing Administrator"
    "Cloud Application Administrator"
    "Conditional Access Administrator"
    "Exchange Administrator"
    "Helpdesk Administrator"
    "Identity Governance Administrator"
    "Password Administrator"
    "Privileged Authentication Administrator"
    "Privileged Role Administrator"
    "Security Administrator"
    "SharePoint Administrator"
    "User Administrator"
)
$requiredRoleIds = @()
$coverageReadError = $null
try {
    $roleDefinitions = @(
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn'
    )
    $requiredRoleIds = @(
        foreach ($name in $adminRoleNames) {
            $role = @($roleDefinitions | Where-Object displayName -eq $name)
            if ($role.Count -ne 1 -or $role[0].isBuiltIn -ne $true -or
                [string]::IsNullOrWhiteSpace([string] $role[0].templateId)) {
                throw "Could not uniquely resolve built-in role '$name' for the coverage advisory."
            }
            [string] $role[0].templateId
        }
    )
}
catch {
    $coverageReadError = $_.Exception.Message
    Write-Warning "Administrator role coverage could not be evaluated: $coverageReadError"
}

$assessment = Get-SecureM365MfaPolicyAssessment `
    -Policies $policies `
    -SecurityDefaultsEnabled $securityDefaultsEnabled `
    -Administrators `
    -RequiredRoleIds $requiredRoleIds `
    -ApprovedExclusions $approvedExclusions `
    -CoverageReadError $coverageReadError

$adminsNotMfaCapable = $null
$missingRegistrationData = $null
$registrationDetails = @()
try {
    $adminRegistration = @(
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$filter=isAdmin%20eq%20true'
    )
    if ($adminRegistration.Count -eq 0) {
        throw "No administrator registration rows were returned; readiness cannot be verified."
    }
    $adminsNotMfaCapable = @($adminRegistration | Where-Object { $_.isMfaCapable -eq $false }).Count
    $missingRegistrationData = @($adminRegistration | Where-Object { $_.isMfaCapable -isnot [bool] }).Count
    $registrationDetails = @(
        $adminRegistration | Where-Object { $_.isMfaCapable -ne $true } |
            Select-Object userDisplayName, userPrincipalName, methodsRegistered
    )
    $registrationEvidence = "Registration advisory: $adminsNotMfaCapable of $($adminRegistration.Count) reported administrators are not MFA-capable; $missingRegistrationData have missing capability data. This includes emergency accounts. Data can lag by up to 36 hours and does not determine the enabled-policy result."
}
catch {
    $registrationEvidence = "Registration advisory: readiness could not be verified. $($_.Exception.Message) Data can lag by up to 36 hours and does not determine the enabled-policy result."
    Write-Warning $registrationEvidence
}

[pscustomobject]@{
    Control = "MFA for administrative roles"
    Status = $assessment.Status
    AssessmentBasis = $assessment.AssessmentBasis
    PolicyFound = $assessment.PolicyFound
    EnabledPolicyFound = $assessment.EnabledPolicyFound
    SecurityDefaultsEnabled = $assessment.SecurityDefaultsEnabled
    ProtectionConfigured = $assessment.ProtectionConfigured
    Resolved = $assessment.Resolved
    Policies = $assessment.Policies
    CoverageVerified = $assessment.CoverageVerified
    MissingAdministrativeRoles = $assessment.MissingAdministrativeRoles
    CoverageEvidence = $assessment.CoverageEvidence
    ExclusionEvidence = $assessment.ExclusionEvidence
    AdministratorsNotMfaCapable = $adminsNotMfaCapable
    AdministratorsWithMissingRegistrationData = $missingRegistrationData
    RegistrationEvidence = $registrationEvidence
    RegistrationDetails = $registrationDetails
    Evidence = $assessment.Evidence
}
