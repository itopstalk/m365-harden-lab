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
    displayName = "CA005 - Require remediation for high user risk"
    state       = "enabledForReportingButNotEnforced"
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

if ($PSCmdlet.ShouldProcess($TenantId.Guid, "Create report-only high user risk remediation policy")) {
    New-SecureM365ConditionalAccessPolicy -BodyParameter $body |
        Select-Object Id, DisplayName, State
}
