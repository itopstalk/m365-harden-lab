#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

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
    -AdditionalScopes "Policy.ReadWrite.ConditionalAccess" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$body = @{
    displayName = "CA002 - Require MFA for all users"
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        clientAppTypes = @("all")
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
        operator = "OR"
        authenticationStrength = @{
            id = "00000000-0000-0000-0000-000000000002"
        }
    }
}

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create report-only all-user MFA policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
