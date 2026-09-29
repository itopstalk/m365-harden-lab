#Requires -Version 7.2

<#
.SYNOPSIS
Reports Microsoft 365 Baseline Security Mode SharePoint and OneDrive settings.

.DESCRIPTION
Returns the four documented SharePoint and OneDrive settings as UNKNOWN. Microsoft
documents the native Set-SPOTenant parameters, but current Microsoft Learn does
not document these properties as Get-SPOTenant output. The tenant-wide permanent
custom-script behavior is exposed only through Baseline Security Mode; per-site
DenyAddAndCustomizePages is not equivalent.

The legacy browser RPS protocol was deprecated for enterprise tenants in October
2025 and can no longer be enabled, but this script still does not claim ENABLED
without authoritative live tenant evidence. No service connection is attempted.

.EXAMPLE
.\63-Test-BaselineSharePointAndOneDrive.ps1

.LINK
https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide
.LINK
https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/get-spotenant
.LINK
https://learn.microsoft.com/en-us/sharepoint/allow-or-prevent-custom-script
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop
$checkedAt = [datetimeoffset]::UtcNow

Get-SecureM365BaselineCatalog |
    Where-Object { $_.SettingId -like "SPO-*" } |
    ForEach-Object {
        $evidence = switch ($_.SettingId) {
            "SPO-001" {
                "Microsoft documents that legacy browser authentication/RPS was deprecated for enterprise tenants in October 2025 and no longer functions, but documents no supported live read property for this setting."
            }
            "SPO-002" {
                "LegacyAuthProtocolsEnabled is documented as a Set-SPOTenant input, but current Get-SPOTenant documentation does not confirm it as returned output."
            }
            "SPO-003" {
                "The permanent tenant-wide new-site behavior is exposed through Baseline Security Mode. Get-SPOSite can read per-site DenyAddAndCustomizePages, which is not equivalent."
            }
            "SPO-004" {
                "DisableSharePointStoreAccess is documented as a Set-SPOTenant input, but current Get-SPOTenant documentation does not confirm it as returned output."
            }
        }
        New-SecureM365BaselineResult -CatalogEntry $_ -Status UNKNOWN -ActualValue $null `
            -Evidence $evidence -CheckedAt $checkedAt
    }
