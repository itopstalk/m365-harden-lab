#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [guid[]] $ApprovedExcludedUserId = @(),
    [guid[]] $ApprovedExcludedGroupId = @(),
    [guid[]] $ApprovedExcludedRoleId = @(),
    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$approvedExclusions = @{
    ApprovedExcludedUserIds  = @(
        $ApprovedExcludedUserId | ForEach-Object { $_.Guid }
    )
    ApprovedExcludedGroupIds = @(
        $ApprovedExcludedGroupId | ForEach-Object { $_.Guid }
    )
    ApprovedExcludedRoleIds  = @(
        $ApprovedExcludedRoleId | ForEach-Object { $_.Guid }
    )
}
$enforcingPolicy = @(
    Get-SecureM365EnabledConditionalAccessPolicy |
    Where-Object {
        (Test-SecureM365CaTargetsAllUsers $_) -and
        (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $_ @approvedExclusions) -and
        (Test-SecureM365CaTargetsAllResources $_) -and
        (Test-SecureM365CaRequiresMfa $_)
    }
)

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
$usersNotMfaCapable = @(
    $activeMembers |
    Where-Object {
        $null -eq $registrationById[$_.id] -or
        $registrationById[$_.id].isMfaCapable -ne $true
    }
)
$protectionConfigured =
    (Get-SecureM365SecurityDefaultsEnabled) -or
    ($enforcingPolicy.Count -gt 0)

[pscustomobject]@{
    Control              = "MFA for all users"
    ProtectionConfigured = $protectionConfigured
    UsersNotMfaCapable   = $usersNotMfaCapable.Count
    Resolved             = $protectionConfigured -and
                           ($usersNotMfaCapable.Count -eq 0)
}

$usersNotMfaCapable |
    Select-Object displayName, userPrincipalName

Test-SecureM365ScoreAction `
    -Title "Ensure multifactor authentication is enabled for all users" `
    -ControlName "MFARegistrationV2"
