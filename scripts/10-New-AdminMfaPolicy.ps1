#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
Creates the administrator MFA Conditional Access policy.
.DESCRIPTION
Creates an immediately enforced policy by default. Validate emergency access
and administrator MFA readiness first. Use -ReportOnly for staged creation.
-WhatIf previews the selected enforced or report-only mode without writing.
.PARAMETER ReportOnly
Create the policy in report-only mode instead of enforcing it immediately.
.EXAMPLE
.\10-New-AdminMfaPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds
.EXAMPLE
.\10-New-AdminMfaPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
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
    -AdditionalScopes @(
        "Policy.ReadWrite.ConditionalAccess"
        "RoleManagement.Read.Directory"
    ) `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

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

$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
$adminRoleTemplateIds = @(
    foreach ($name in $adminRoleNames) {
        $role = $roleDefinitions |
            Where-Object { $_.DisplayName -eq $name } |
            Select-Object -First 1
        if ($null -eq $role) {
            throw "Could not resolve the built-in role '$name'."
        }
        $role.TemplateId
    }
)

$policyMode = if ($ReportOnly) { "report-only" } else { "enforced" }
$policyState = if ($ReportOnly) { "enabledForReportingButNotEnforced" } else { "enabled" }
$body = @{
    displayName = "CA001 - Require MFA for administrator roles"
    state       = $policyState
    conditions  = @{
        clientAppTypes = @("all")
        applications   = @{
            includeApplications = @("All")
            excludeApplications = @()
        }
        users          = @{
            includeRoles = $adminRoleTemplateIds
            excludeUsers = @($EmergencyAccessAccountId.Guid)
        }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("mfa")
    }
}

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create $policyMode administrator MFA policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
