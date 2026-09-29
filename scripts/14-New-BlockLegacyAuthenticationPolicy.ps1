#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
Creates the legacy-authentication block Conditional Access policy.
.DESCRIPTION
Creates an immediately enforced policy by default. Validate emergency access
and confirm required clients use modern authentication first. Use -ReportOnly
for staged creation. -WhatIf previews the selected mode without writing.
.PARAMETER ReportOnly
Create the policy in report-only mode instead of enforcing it immediately.
.EXAMPLE
.\14-New-BlockLegacyAuthenticationPolicy.ps1 -TenantId $TenantId -ReportOnly
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [guid[]] $TemporaryExceptionAccountId = @(),
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
    displayName = "CA003 - Block legacy authentication"
    state       = $policyState
    conditions  = @{
        clientAppTypes = @(
            "exchangeActiveSync"
            "other"
        )
        applications   = @{
            includeApplications = @("All")
            excludeApplications = @()
        }
        users          = @{
            includeUsers = @("All")
            excludeUsers = @(
                $TemporaryExceptionAccountId |
                ForEach-Object { $_.Guid }
            )
        }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }
}

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create $policyMode legacy authentication block policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
