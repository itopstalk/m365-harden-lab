#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
Creates the sign-in risk Conditional Access policy.
.DESCRIPTION
Creates an immediately enforced policy by default. Validate emergency access
and MFA readiness first. Use -ReportOnly for staged creation. -WhatIf previews
the selected enforced or report-only mode without writing.
.PARAMETER ReportOnly
Create the policy in report-only mode instead of enforcing it immediately.
.EXAMPLE
.\16-New-SignInRiskPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [ValidateCount(2, 10)]
    [guid[]] $EmergencyAccessAccountId,

    [switch] $UseDeviceCode,
    [switch] $ReportOnly
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Policy.ReadWrite.ConditionalAccess" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$policyMode = if ($ReportOnly) { "report-only" } else { "enforced" }
$policyState = if ($ReportOnly) { "enabledForReportingButNotEnforced" } else { "enabled" }
$body = @{
    displayName = "CA004 - Require MFA for medium and high sign-in risk"
    state       = $policyState
    conditions  = @{
        clientAppTypes   = @("all")
        signInRiskLevels = @("medium", "high")
        applications     = @{
            includeApplications = @("All")
            excludeApplications = @()
        }
        users            = @{
            includeUsers = @("All")
            excludeUsers = @($EmergencyAccessAccountId.Guid)
        }
    }
    grantControls = @{
        operator = "OR"
        authenticationStrength = @{
            id = "00000000-0000-0000-0000-000000000002"
        }
    }
    sessionControls = @{
        signInFrequency = @{
            isEnabled          = $true
            frequencyInterval  = "everyTime"
            authenticationType = "primaryAndSecondaryAuthentication"
        }
    }
}

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create $policyMode sign-in risk policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
