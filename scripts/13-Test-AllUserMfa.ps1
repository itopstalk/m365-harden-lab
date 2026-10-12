#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Checks whether an all-user MFA policy is present and enabled.

.DESCRIPTION
Resolved is true when Security Defaults is enabled or an enabled Conditional
Access policy requires MFA and directly targets All users. Recognizes the
authentication strength configured by script 12 and uses the same policy
assessment as script 99. PolicyFound refers to the actual policy, not Secure Score.

Policy IDs, names, states, and exclusions are reported. Complete coverage is a
separate CoverageVerified advisory. Unapproved exclusions, narrower conditions,
and incomplete MFA registration do not change the enabled-policy result.
Disabled and report-only policies do not pass.

Registration readiness is advisory for enabled member accounts, including
emergency accounts. Missing data and failed reads are reported explicitly.
Registration data can lag by up to 36 hours. No Secure Score snapshot is consulted
and no tenant settings are changed. This checks configuration, not every sign-in.

.PARAMETER TenantId
The Microsoft Entra tenant GUID.

.PARAMETER ApprovedExcludedUserId
Reviewed user exclusions, such as the emergency account IDs supplied to script 12.
Used only for the separate coverage advisory; not required to find the policy.

.PARAMETER ApprovedExcludedGroupId
Reviewed group exclusions for the coverage advisory.

.PARAMETER ApprovedExcludedRoleId
Reviewed role-template exclusions for the coverage advisory.

.EXAMPLE
.\13-Test-AllUserMfa.ps1 -TenantId $TenantId

.EXAMPLE
.\13-Test-AllUserMfa.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

.LINK
https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength
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
$assessment = Get-SecureM365MfaPolicyAssessment `
    -Policies $policies `
    -SecurityDefaultsEnabled $securityDefaultsEnabled `
    -ApprovedExclusions $approvedExclusions

$usersNotMfaCapable = $null
$missingRegistrationData = $null
$registrationDetails = @()
try {
    $users = @(
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999'
    )
    foreach ($user in $users) {
        if (
            [string]::IsNullOrWhiteSpace([string] $user.id) -or
            $user.accountEnabled -isnot [bool] -or
            $user.userType -notin @("Member", "Guest")
        ) {
            throw "The user inventory is missing required identity, accountEnabled, or userType data."
        }
    }
    $activeMembers = @($users | Where-Object { $_.accountEnabled -and $_.userType -eq "Member" })
    if ($activeMembers.Count -eq 0) {
        throw "No enabled member accounts were returned; registration readiness cannot be verified."
    }
    $registration = @(
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    )
    $registrationById = @{}
    foreach ($row in $registration) {
        if ([string]::IsNullOrWhiteSpace([string] $row.id) -or $registrationById.ContainsKey($row.id)) {
            throw "The registration report contains a missing or duplicate user ID."
        }
        $registrationById[$row.id] = $row
    }
    $usersNotMfaCapable = @(
        $activeMembers | Where-Object {
            $registrationById[$_.id].isMfaCapable -is [bool] -and
            $registrationById[$_.id].isMfaCapable -eq $false
        }
    ).Count
    $missingRegistrationData = @(
        $activeMembers | Where-Object { $registrationById[$_.id].isMfaCapable -isnot [bool] }
    ).Count
    $registrationDetails = @(
        $activeMembers | Where-Object {
            $registrationById[$_.id].isMfaCapable -isnot [bool] -or
            $registrationById[$_.id].isMfaCapable -eq $false
        } |
            Select-Object displayName, userPrincipalName
    )
    $registrationEvidence = "Registration advisory: $usersNotMfaCapable of $($activeMembers.Count) enabled member accounts are not reported MFA-capable; $missingRegistrationData have missing capability data. This includes emergency accounts. Data can lag by up to 36 hours and does not determine the enabled-policy result."
}
catch {
    $usersNotMfaCapable = $null
    $missingRegistrationData = $null
    $registrationDetails = @()
    $registrationEvidence = "Registration advisory: readiness could not be verified. $($_.Exception.Message) Data can lag by up to 36 hours and does not determine the enabled-policy result."
    Write-Warning $registrationEvidence
}

[pscustomobject]@{
    Control = "MFA for all users"
    Status = $assessment.Status
    AssessmentBasis = $assessment.AssessmentBasis
    PolicyFound = $assessment.PolicyFound
    EnabledPolicyFound = $assessment.EnabledPolicyFound
    SecurityDefaultsEnabled = $assessment.SecurityDefaultsEnabled
    ProtectionConfigured = $assessment.ProtectionConfigured
    Resolved = $assessment.Resolved
    Policies = $assessment.Policies
    CoverageVerified = $assessment.CoverageVerified
    CoverageEvidence = $assessment.CoverageEvidence
    ExclusionEvidence = $assessment.ExclusionEvidence
    UsersNotMfaCapable = $usersNotMfaCapable
    UsersWithMissingRegistrationData = $missingRegistrationData
    RegistrationEvidence = $registrationEvidence
    RegistrationDetails = $registrationDetails
    Evidence = $assessment.Evidence
}
