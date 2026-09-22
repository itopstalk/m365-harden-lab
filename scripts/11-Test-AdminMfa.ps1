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
$adminRoleNames = @(
    "Global Administrator"
    "Application Administrator"
    "Authentication Administrator"
    "Authentication Policy Administrator"
    "Billing Administrator"
    "Cloud Application Administrator"
    "Conditional Access Administrator"
    "Exchange Administrator"
    "Helpdesk Administrator"
    "Identity Governance Administrator"
    "Password Administrator"
    "Privileged Authentication Administrator"
    "Privileged Role Administrator"
    "Security Administrator"
    "SharePoint Administrator"
    "User Administrator"
)

$roleDefinitions = Get-SecureM365GraphCollection `
    -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName&$top=999'
$requiredRoleIds = @(
    $roleDefinitions |
    Where-Object { $_.displayName -in $adminRoleNames } |
    ForEach-Object { $_.templateId }
)

$policies = @(Get-SecureM365EnabledConditionalAccessPolicy)
$allUsersPolicy = @(
    $policies |
    Where-Object {
        (Test-SecureM365CaTargetsAllUsers $_) -and
        (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $_ @approvedExclusions) -and
        (Test-SecureM365CaTargetsAllResources $_) -and
        (Test-SecureM365CaRequiresMfa $_)
    }
).Count -gt 0

$coveredRoleIds = @(
    $policies |
    Where-Object {
        (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $_ @approvedExclusions) -and
        (Test-SecureM365CaTargetsAllResources $_) -and
        (Test-SecureM365CaRequiresMfa $_)
    } |
    ForEach-Object { @($_.conditions.users.includeRoles) }
) | Select-Object -Unique

$missingRoles = @(
    $requiredRoleIds |
    Where-Object { $_ -notin $coveredRoleIds }
)
$adminRegistration = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$filter=isAdmin%20eq%20true'
)
$adminsNotMfaCapable = @(
    $adminRegistration |
    Where-Object { $_.isMfaCapable -ne $true }
)
$protectionConfigured =
    (Get-SecureM365SecurityDefaultsEnabled) -or
    $allUsersPolicy -or
    ($requiredRoleIds.Count -gt 0 -and $missingRoles.Count -eq 0)

[pscustomobject]@{
    Control                     = "MFA for administrative roles"
    ProtectionConfigured        = $protectionConfigured
    MissingAdministrativeRoles  = $missingRoles
    AdministratorsNotMfaCapable = $adminsNotMfaCapable.Count
    Resolved                    = $protectionConfigured -and
                                  ($adminsNotMfaCapable.Count -eq 0)
}

$adminsNotMfaCapable |
    Select-Object userDisplayName, userPrincipalName, methodsRegistered

Test-SecureM365ScoreAction `
    -Title "Ensure multifactor authentication is enabled for all users in administrative roles" `
    -ControlName "AdminMFAV2"
