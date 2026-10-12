#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Checks whether a matching sign-in risk MFA policy is present and enabled.

.DESCRIPTION
Uses the same assessment as script 99. A matching policy targets All users,
covers medium and high sign-in risk, requires MFA, and requires every-time
primary-and-secondary reauthentication. Recognizes script 16's MFA strength.
Disabled and report-only policies are reported but do not pass.

Resolved means a matching enabled policy was found, not that every user,
resource, or sign-in is protected. Coverage and exclusions are separate
advisories. Security Defaults is not a substitute for a sign-in risk policy.
No registration report, risky sign-in event, or Secure Score snapshot is needed.
This script reads configuration only and does not modify tenant settings.

.PARAMETER TenantId
The Microsoft Entra tenant GUID.

.PARAMETER ApprovedExcludedUserId
Reviewed user exclusions, such as the emergency account IDs supplied to script 16.
Used only for the coverage advisory, not the enabled-policy result.

.PARAMETER ApprovedExcludedGroupId
Reviewed group exclusions for the coverage advisory.

.PARAMETER ApprovedExcludedRoleId
Reviewed role-template exclusions for the coverage advisory.

.EXAMPLE
.\17-Test-SignInRiskPolicy.ps1 -TenantId $TenantId

.EXAMPLE
.\17-Test-SignInRiskPolicy.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

.LINK
https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in
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
$assessment = Get-SecureM365MfaPolicyAssessment -SignInRisk `
    -Policies $policies -ApprovedExclusions $approvedExclusions

[pscustomobject]@{
    Control = "Sign-in risk policy"
    Status = $assessment.Status
    AssessmentBasis = $assessment.AssessmentBasis
    PolicyFound = $assessment.PolicyFound
    EnabledPolicyFound = $assessment.EnabledPolicyFound
    ProtectionConfigured = $assessment.ProtectionConfigured
    Resolved = $assessment.Resolved
    MatchingPolicies = @($assessment.Policies | Where-Object State -eq "enabled" | ForEach-Object DisplayName)
    Policies = $assessment.Policies
    CoverageVerified = $assessment.CoverageVerified
    CoverageEvidence = $assessment.CoverageEvidence
    ExclusionEvidence = $assessment.ExclusionEvidence
    Evidence = $assessment.Evidence
}
