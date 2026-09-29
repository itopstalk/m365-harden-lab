#Requires -Version 7.2

<#
.SYNOPSIS
Builds a consolidated read-only Microsoft 365 Baseline Security Mode report.

.DESCRIPTION
Runs each workload-specific validator and returns one report containing all 20
settings plus summary totals. Queryable settings use their native Microsoft
Graph or Exchange Online controls. Unsupported, UI-only, preview, set-only, and
multi-system settings remain UNKNOWN with explicit evidence.

This validates underlying settings only. It does not read the Baseline Security
Mode UI toggle, draft/preview state, or impact-report state because Microsoft
documents no supported API for those surfaces. It never mutates tenant state.

.PARAMETER TenantId
The intended Microsoft Entra tenant GUID.

.PARAMETER UseGraphDeviceCode
Use device-code authentication for Microsoft Graph.

.PARAMETER UseGraphBrowserPkce
Use browser authorization code authentication with PKCE.

.PARAMETER ExchangeUserPrincipalName
Optional UPN used for modern Exchange Online interactive authentication.

.PARAMETER SkipExchange
Do not attempt Exchange Online authentication. EXO-001 remains UNKNOWN with an
explicit skip reason.

.EXAMPLE
$report = .\69-Test-BaselineSecurityMode.ps1 -TenantId $TenantId -UseGraphBrowserPkce
$report.Results | Export-Csv .\baseline.csv -NoTypeInformation

.LINK
https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,
    [switch] $UseGraphDeviceCode,
    [switch] $UseGraphBrowserPkce,
    [string] $ExchangeUserPrincipalName,
    [switch] $SkipExchange
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

$results = [System.Collections.Generic.List[object]]::new()
foreach ($path in @(
    "62-Test-BaselineAuthenticationAndApps.ps1"
    "63-Test-BaselineSharePointAndOneDrive.ps1"
    "65-Test-BaselineMicrosoft365Apps.ps1"
    "66-Test-BaselineTeamsAndCollaboration.ps1"
)) {
    $parameters = @{}
    if ($path -like "62-*") {
        $parameters = @{
            TenantId = $TenantId
            UseGraphDeviceCode = $UseGraphDeviceCode
            UseGraphBrowserPkce = $UseGraphBrowserPkce
        }
    }
    foreach ($result in @(& (Join-Path $PSScriptRoot $path) @parameters)) {
        [void] $results.Add($result)
    }
}

if ($SkipExchange) {
    $entry = Get-SecureM365BaselineCatalog | Where-Object SettingId -eq "EXO-001"
    [void] $results.Add((New-SecureM365BaselineResult -CatalogEntry $entry -Status UNKNOWN `
        -ActualValue $null -Evidence "Exchange Online check skipped by operator." `
        -CheckedAt ([datetimeoffset]::UtcNow)))
}
else {
    $exchangeParameters = @{ TenantId = $TenantId }
    if (-not [string]::IsNullOrWhiteSpace($ExchangeUserPrincipalName)) {
        $exchangeParameters.ExchangeUserPrincipalName = $ExchangeUserPrincipalName
    }
    foreach ($result in @(& (Join-Path $PSScriptRoot "64-Test-BaselineExchangeOnline.ps1") @exchangeParameters)) {
        [void] $results.Add($result)
    }
}

New-SecureM365BaselineReport -TenantId $TenantId -Results $results.ToArray()
