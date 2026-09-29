#Requires -Version 7.2
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
Tests the Exchange Online EWS control used by Microsoft 365 Baseline Security Mode.

.DESCRIPTION
Uses modern interactive Exchange Online authentication, validates the connected
tenant, and reads Get-OrganizationConfig. It never changes Exchange configuration.
EwsEnabled null is treated as enabled, as documented by Microsoft, so only an
explicit false value satisfies the baseline.

Connection, tenant-validation, permission, empty, and malformed-data failures
return UNKNOWN rather than DISABLED.

.PARAMETER TenantId
The intended Microsoft Entra tenant GUID.

.PARAMETER ExchangeUserPrincipalName
Optional administrator UPN supplied to Connect-ExchangeOnline. No password or
token is accepted or stored.

.EXAMPLE
.\64-Test-BaselineExchangeOnline.ps1 -TenantId $TenantId -ExchangeUserPrincipalName admin@contoso.com

.LINK
https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-control-access-to-ews-in-exchange
.LINK
https://learn.microsoft.com/en-us/powershell/module/exchange/connect-exchangeonline
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,
    [string] $ExchangeUserPrincipalName
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop
$entry = Get-SecureM365BaselineCatalog | Where-Object SettingId -eq "EXO-001"
$checkedAt = [datetimeoffset]::UtcNow

try {
    $connectParameters = @{ ShowBanner = $false; ErrorAction = "Stop" }
    if (-not [string]::IsNullOrWhiteSpace($ExchangeUserPrincipalName)) {
        $connectParameters.UserPrincipalName = $ExchangeUserPrincipalName
    }
    Connect-ExchangeOnline @connectParameters

    $connections = @(Get-ConnectionInformation -ErrorAction Stop)
    $matchingConnections = @(
        $connections | Where-Object {
            [string] $_.TenantID -eq $TenantId.Guid -and
            [string] $_.State -eq "Connected"
        }
    )
    if ($matchingConnections.Count -ne 1) {
        throw "Exchange Online did not return exactly one connected session for tenant '$($TenantId.Guid)'."
    }

    $configurations = @(Get-OrganizationConfig -ErrorAction Stop)
    if ($configurations.Count -ne 1) {
        throw "Exchange Online returned $($configurations.Count) organization configurations; exactly one is required."
    }
    $ewsEnabled = $configurations[0].EwsEnabled
    if ($null -ne $ewsEnabled -and $ewsEnabled -isnot [bool]) {
        throw "Get-OrganizationConfig returned a non-Boolean EwsEnabled value."
    }
    $resolved = $ewsEnabled -eq $false
    New-SecureM365BaselineResult -CatalogEntry $entry `
        -Status $(if ($resolved) { "ENABLED" } else { "DISABLED" }) `
        -Resolved $resolved -ActualValue $ewsEnabled `
        -Evidence $(if ($null -eq $ewsEnabled) {
            "Get-OrganizationConfig returned EwsEnabled = null, which Microsoft documents as allowing EWS."
        } else {
            "Get-OrganizationConfig returned EwsEnabled = $ewsEnabled."
        }) -CheckedAt $checkedAt
}
catch {
    New-SecureM365BaselineResult -CatalogEntry $entry -Status UNKNOWN -ActualValue $null `
        -Evidence "Exchange Online read failed: $($_.Exception.Message)" -CheckedAt $checkedAt
}
