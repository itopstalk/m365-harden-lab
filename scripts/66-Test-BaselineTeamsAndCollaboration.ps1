#Requires -Version 7.2

<#
.SYNOPSIS
Reports Teams Rooms and collaboration controls used by Baseline Security Mode.

.DESCRIPTION
Returns both documented room-device settings as UNKNOWN. The resource-account
file restriction is a preview Set-SPOTenant parameter that may not exist and is
not documented as Get-SPOTenant output. The compliant-device setting spans a
dynamic group, Conditional Access, Intune compliance, and an Entra ID Governance
access package; Microsoft documents no single authoritative Baseline Security
Mode read API or stable object identity that proves the complete configuration.

This script does not connect to Teams because neither setting is a Teams
PowerShell meeting-policy property. It never changes tenant state.

.EXAMPLE
.\66-Test-BaselineTeamsAndCollaboration.ps1

.LINK
https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide
.LINK
https://learn.microsoft.com/en-us/microsoftteams/rooms/block-non-compliant-teams-rooms-devices
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop
$checkedAt = [datetimeoffset]::UtcNow

Get-SecureM365BaselineCatalog |
    Where-Object Workload -eq "Teams / Collaboration" |
    ForEach-Object {
        $evidence = if ($_.SettingId -eq "ROOMS-001") {
            "RestrictResourceAccountAccess is preview, may not exist in the tenant, and is not documented as Get-SPOTenant output."
        }
        else {
            "The documented control requires correlated Entra dynamic-group, Conditional Access, Intune compliance, and access-package evidence; no single BSM read API or stable BSM object identity is documented."
        }
        New-SecureM365BaselineResult -CatalogEntry $_ -Status UNKNOWN -ActualValue $null `
            -Evidence $evidence -CheckedAt $checkedAt
    }
