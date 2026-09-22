#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [guid[]] $TemporaryExceptionAccountId = @(),
    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Policy.ReadWrite.ConditionalAccess" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$body = @{
    displayName = "CA003 - Block legacy authentication"
    state       = "enabledForReportingButNotEnforced"
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

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create report-only legacy authentication block policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
