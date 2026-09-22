#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$actions = @(
    @{ Title = "Ensure multifactor authentication is enabled for all users in administrative roles"; ControlName = "AdminMFAV2" }
    @{ Title = "Ensure multifactor authentication is enabled for all users"; ControlName = "MFARegistrationV2" }
    @{ Title = "Enable Conditional Access policies to block legacy authentication"; ControlName = "BlockLegacyAuthentication" }
    @{ Title = "Enable Microsoft Entra ID Identity Protection sign-in risk policies"; ControlName = "SigninRiskPolicy" }
    @{ Title = "Enable Microsoft Entra ID Identity Protection user risk policies"; ControlName = "UserRiskPolicy" }
    @{ Title = "Ensure user consent to apps accessing company data on their behalf is not allowed"; ControlName = "IntegratedApps" }
    @{ Title = "Only invited users should be automatically admitted to Teams meetings"; ControlName = "meeting_autoadmitusers_v1" }
    @{ Title = "Configure which users are allowed to present in Teams meetings"; ControlName = "meeting_designatedpresenter_v1" }
    @{ Title = "Restrict anonymous users from joining meetings"; ControlName = "meeting_restrictanonymousjoin_v1" }
    @{ Title = "Use least privileged administrative roles"; ControlName = "RoleOverlap" }
    @{ Title = "Ensure 'Self service password reset enabled' is set to 'All'"; ControlName = "SelfServicePasswordReset" }
)

Reset-SecureM365ScoreCache
$actions |
    ForEach-Object {
        Test-SecureM365ScoreAction `
            -Title $_.Title `
            -ControlName $_.ControlName
    } |
    Format-Table Action, CurrentScore, MaximumScore, Resolved, ScoreSnapshotAt -AutoSize
