#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
Creates the high user risk remediation Conditional Access policy.
.DESCRIPTION
Creates an immediately enforced policy by default. Validate emergency access,
MFA, and password-change readiness first. Use -ReportOnly for staged creation.
-WhatIf previews the selected enforced or report-only mode without writing.
.PARAMETER ReportOnly
Create the policy in report-only mode instead of enforcing it immediately.
.EXAMPLE
.\18-New-UserRiskPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
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
    displayName = "CA005 - Require remediation for high user risk"
    state       = $policyState
    conditions  = @{
        clientAppTypes = @("all")
        userRiskLevels = @("high")
        applications   = @{
            includeApplications = @("All")
            excludeApplications = @()
        }
        users          = @{
            includeUsers = @("All")
            excludeUsers = @($EmergencyAccessAccountId.Guid)
        }
    }
    grantControls = @{
        operator        = "AND"
        builtInControls = @("passwordChange")
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

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create $policyMode high user risk remediation policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
