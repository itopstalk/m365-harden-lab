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

$users = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999'
)
$activeMembers = @(
    $users |
    Where-Object {
        $_.accountEnabled -eq $true -and
        $_.userType -eq "Member"
    }
)
$registration = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
)
$registrationById = @{}
foreach ($row in $registration) {
    $registrationById[$row.id] = $row
}
$notEnabled = @(
    $activeMembers |
    Where-Object {
        $null -eq $registrationById[$_.id] -or
        $registrationById[$_.id].isSsprEnabled -ne $true
    }
)
$notCapable = @(
    $activeMembers |
    Where-Object {
        $null -eq $registrationById[$_.id] -or
        $registrationById[$_.id].isSsprCapable -ne $true
    }
)

[pscustomobject]@{
    Control             = "SSPR enabled for all users"
    ActiveMemberUsers   = $activeMembers.Count
    UsersNotEnabled     = $notEnabled.Count
    UsersNotSsprCapable = $notCapable.Count
    Resolved            = $notEnabled.Count -eq 0
}

$notEnabled |
    Select-Object displayName, userPrincipalName

Test-SecureM365ScoreAction `
    -Title "Ensure 'Self service password reset enabled' is set to 'All'" `
    -ControlName "SelfServicePasswordReset"
