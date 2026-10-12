#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Checks whether a matching user-risk remediation policy is present and enabled.

.DESCRIPTION
Uses the same assessment as script 99. A matching policy targets All users,
covers high user risk, requires MFA AND exactly one remediation control, and
requires every-time primary-and-secondary reauthentication. Recognizes script
18's passwordChange policy and modern riskRemediation policies with MFA strength.
The two remediation controls must not be combined. Disabled and report-only
policies are reported but do not pass.

Resolved means a matching enabled policy was found, not that every account or
sign-in is protected or that a user has completed remediation. Coverage and
exclusions are separate advisories. Security Defaults is not a substitute.
No risky-user event, registration report, or Secure Score snapshot is needed.
This script reads configuration only and does not modify tenant settings.

.PARAMETER TenantId
The Microsoft Entra tenant GUID.

.PARAMETER ApprovedExcludedUserId
Reviewed user exclusions, such as the emergency account IDs supplied to script 18.
Used only for the coverage advisory, not the enabled-policy result.

.PARAMETER ApprovedExcludedGroupId
Reviewed group exclusions for the coverage advisory.

.PARAMETER ApprovedExcludedRoleId
Reviewed role-template exclusions for the coverage advisory.

.EXAMPLE
.\19-Test-UserRiskPolicy.ps1 -TenantId $TenantId

.EXAMPLE
.\19-Test-UserRiskPolicy.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

.LINK
https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user
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
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
        -Headers @{ Prefer = "include-unknown-enum-members" }
)
$assessment = Get-SecureM365MfaPolicyAssessment -UserRisk `
    -Policies $policies -ApprovedExclusions $approvedExclusions

[pscustomobject]@{
    Control = "User risk policy"
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
