#Requires -Version 7.2

<#
.SYNOPSIS
Reports Microsoft 365 Apps controls used by Microsoft 365 Baseline Security Mode.

.DESCRIPTION
Returns the nine Office client and file controls as UNKNOWN because Microsoft
documents them through Baseline Security Mode, Office Cloud Policy Service,
Trust Center, and impact reports, but documents no supported PowerShell or API
read surface for their tenant state. No success-shaped inference is made from
secure Office defaults, because Baseline Security Mode also locks local overrides.

.EXAMPLE
.\65-Test-BaselineMicrosoft365Apps.ps1

.LINK
https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide
.LINK
https://learn.microsoft.com/en-us/microsoft-365-apps/admin-center/overview-cloud-policy
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop
$checkedAt = [datetimeoffset]::UtcNow

Get-SecureM365BaselineCatalog |
    Where-Object Workload -eq "Microsoft 365 Apps" |
    ForEach-Object {
        New-SecureM365BaselineResult -CatalogEntry $_ -Status UNKNOWN -ActualValue $null `
            -Evidence "Microsoft documents no supported PowerShell or API read surface for this Baseline Security Mode/Office Cloud Policy Service state. Review the Baseline Security Mode UI and impact report." `
            -CheckedAt $checkedAt
    }
