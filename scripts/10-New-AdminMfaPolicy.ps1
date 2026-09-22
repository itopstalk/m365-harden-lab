#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.Governance

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [ValidateCount(2, 10)]
    [guid[]] $EmergencyAccessAccountId,

    [switch] $UseDeviceCode
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

$body = @{
    displayName = "CA001 - Require MFA for administrator roles"
    state       = "enabledForReportingButNotEnforced"
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

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create report-only administrator MFA policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
