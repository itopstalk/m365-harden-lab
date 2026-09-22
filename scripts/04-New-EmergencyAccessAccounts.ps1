#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Creates cloud-only emergency access accounts with permanent Global Administrator access.

.DESCRIPTION
Uses the tenant's initial, verified, managed onmicrosoft.com domain. Checks every
requested username before making changes and refuses to modify existing users.
Prompts securely for distinct passwords of 32-256 printable ASCII characters,
including at least three character categories, and confirms each password.
Passwords are not printed or saved. Store them securely before running this script.
WhatIf performs discovery without requesting write scopes or prompting for passwords.

Creation does not enroll MFA, change Conditional Access or security defaults, or
configure monitoring. Complete those safeguards before relying on these accounts.
Partial changes are not rolled back; review any reported accounts before retrying.

.PARAMETER TenantId
The Microsoft Entra tenant GUID in the Microsoft 365 worldwide cloud.

.PARAMETER AccountName
Two to ten distinct username prefixes, without a domain. Use letters, numbers,
hyphens, or underscores, starting with a letter or number (maximum 64 characters).

.PARAMETER UseDeviceCode
Use device-code authentication instead of interactive browser authentication.

.EXAMPLE
.\04-New-EmergencyAccessAccounts.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
$accounts = @(.\04-New-EmergencyAccessAccounts.ps1 -TenantId $TenantId)
$accounts | Select-Object Id, UserPrincipalName, RoleAssignmentId
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [ValidateCount(2, 10)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')]
    [string[]] $AccountName = @(
        "emergency-access-01"
        "emergency-access-02"
    ),

    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"

if ($TenantId -eq [guid]::Empty) {
    throw "Supply a nonempty Microsoft Entra tenant GUID."
}
if (@($AccountName | Sort-Object -Unique).Count -ne $AccountName.Count) {
    throw "Supply at least two distinct account names; names are not case-sensitive."
}

Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

$additionalScopes = @("Domain.Read.All")
if (-not $WhatIfPreference) {
    $additionalScopes += @(
        "User.Create"
        "RoleManagement.ReadWrite.Directory"
    )
}

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes $additionalScopes `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$initialDomains = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isInitial,isVerified,authenticationType' |
        Where-Object { $_.isInitial -eq $true }
)
if (
    $initialDomains.Count -ne 1 -or
    $initialDomains[0].isVerified -ne $true -or
    $initialDomains[0].authenticationType -ne "Managed" -or
    $initialDomains[0].id -notmatch '^[a-z0-9-]+\.onmicrosoft\.com$'
) {
    throw "Expected one initial, verified, managed onmicrosoft.com domain. No accounts were created."
}
$domain = $initialDomains[0].id

$globalAdministratorTemplateId = "62e90394-69f5-4237-9190-012177145e10"
$globalAdministratorRoles = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,isBuiltIn' |
        Where-Object {
            $_.templateId -eq $globalAdministratorTemplateId -and
            $_.isBuiltIn -eq $true
        }
)
if (
    $globalAdministratorRoles.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace($globalAdministratorRoles[0].id)
) {
    throw "Could not resolve the built-in Global Administrator role. No accounts were created."
}
$roleDefinitionId = $globalAdministratorRoles[0].id

$plannedAccounts = @(
    foreach ($name in $AccountName) {
        $upn = "$name@$domain"
        $filter = [uri]::EscapeDataString("userPrincipalName eq '$upn'")
        $existingUsers = @(
            Get-SecureM365GraphCollection `
                -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=id,userPrincipalName"
        )
        if ($existingUsers.Count -gt 0) {
            $existingIds = $existingUsers.id -join ", "
            throw "User '$upn' already exists ($existingIds). No accounts were created. Review the existing emergency accounts or choose different AccountName values; this script never resets or elevates existing users."
        }

        [pscustomobject]@{
            UserPrincipalName = $upn
            DisplayName       = "Emergency access - $name"
            MailNickname      = $name
        }
    }
)

$operation = "Create cloud-only users and assign permanent, tenant-wide Global Administrator: $($plannedAccounts.UserPrincipalName -join ', ')"
if (-not $PSCmdlet.ShouldProcess($TenantId.Guid, $operation)) {
    return
}

Write-Warning "Store a different randomly generated password for each account in your approved emergency credential store before entering it. Do not enable HTTP request logging or debugging."

$passwords = @{}
$createdAccounts = [System.Collections.Generic.List[object]]::new()
$creationAttempted = $false
$completed = $false

try {
    # Validate every password before the first write to avoid a partially configured pair.
    foreach ($account in $plannedAccounts) {
        $upn = $account.UserPrincipalName
        $passwords[$upn] = Read-Host "Enter the stored password for $upn (32-256 characters)" -AsSecureString
        if ($passwords[$upn].Length -lt 32 -or $passwords[$upn].Length -gt 256) {
            throw "The password for '$upn' must contain 32-256 characters. No accounts were created."
        }

        $confirmation = $null
        $plainPassword = $null
        $plainConfirmation = $null
        try {
            $confirmation = Read-Host "Confirm the password for $upn" -AsSecureString
            $plainPassword = [System.Net.NetworkCredential]::new("", $passwords[$upn]).Password
            $plainConfirmation = [System.Net.NetworkCredential]::new("", $confirmation).Password

            if (-not [string]::Equals($plainPassword, $plainConfirmation, [StringComparison]::Ordinal)) {
                throw "The passwords for '$upn' do not match. No accounts were created."
            }
            $characterCategories = @(
                @("[a-z]", "[A-Z]", "[0-9]", "[^a-zA-Z0-9]") |
                    Where-Object { $plainPassword -cmatch $_ }
            )
            if ($plainPassword -cmatch '[^\x20-\x7E]' -or $characterCategories.Count -lt 3) {
                throw "Use printable ASCII and at least three categories (lowercase, uppercase, digits, symbols) for '$upn'. No accounts were created."
            }
            foreach ($otherUpn in $passwords.Keys) {
                if (
                    $otherUpn -ne $upn -and
                    [string]::Equals(
                        $plainPassword,
                        [System.Net.NetworkCredential]::new("", $passwords[$otherUpn]).Password,
                        [StringComparison]::Ordinal
                    )
                ) {
                    throw "Emergency access accounts must have different passwords. No accounts were created."
                }
            }
        }
        finally {
            $plainPassword = $null
            $plainConfirmation = $null
            if ($null -ne $confirmation) {
                $confirmation.Dispose()
            }
        }
    }

    foreach ($account in $plannedAccounts) {
        $upn = $account.UserPrincipalName
        $userBody = @{
            accountEnabled    = $true
            displayName       = $account.DisplayName
            mailNickname      = $account.MailNickname
            userPrincipalName = $upn
            userType          = "Member"
            passwordPolicies  = "DisablePasswordExpiration"
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $false
                password = [System.Net.NetworkCredential]::new("", $passwords[$upn]).Password
            }
        }
        $jsonBody = $null
        try {
            $jsonBody = $userBody | ConvertTo-Json -Depth 4
            $creationAttempted = $true
            $user = Invoke-MgGraphRequest `
                -Method POST `
                -Uri 'https://graph.microsoft.com/v1.0/users' `
                -Body $jsonBody `
                -ContentType "application/json" `
                -Debug:$false `
                -Verbose:$false `
                -ErrorAction Stop
        }
        finally {
            $userBody.passwordProfile.password = $null
            $jsonBody = $null
        }

        $userId = [guid]::Empty
        if (
            -not [guid]::TryParse([string] $user.id, [ref] $userId) -or
            $userId -eq [guid]::Empty
        ) {
            throw "Graph did not return a valid object ID for '$upn'. Check Users in the Entra admin center before retrying."
        }
        if ($user.userPrincipalName -ne $upn) {
            throw "Graph returned user '$($user.userPrincipalName)' ($($userId.Guid)) instead of '$upn'. No role was assigned to this user. Review Users in the Entra admin center before retrying."
        }

        $result = [pscustomobject]@{
            Id                = $userId.Guid
            UserPrincipalName = $upn
            RoleAssignmentId  = $null
        }
        [void] $createdAccounts.Add($result)

        $assignmentBody = @{
            principalId      = $userId.Guid
            roleDefinitionId = $roleDefinitionId
            directoryScopeId = "/"
        } | ConvertTo-Json

        $assignment = Invoke-MgGraphRequest `
            -Method POST `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' `
            -Body $assignmentBody `
            -ContentType "application/json" `
            -ErrorAction Stop

        if (
            [string]::IsNullOrWhiteSpace($assignment.id) -or
            $assignment.principalId -ne $userId.Guid -or
            $assignment.roleDefinitionId -ne $roleDefinitionId -or
            $assignment.directoryScopeId -ne "/"
        ) {
            throw "The Global Administrator assignment for '$upn' ($($userId.Guid)) was not confirmed. Review the account's role assignments before retrying."
        }
        $result.RoleAssignmentId = $assignment.id
    }
    $completed = $true
}
finally {
    foreach ($password in $passwords.Values) {
        $password.Dispose()
    }
    if ($creationAttempted -and -not $completed) {
        Write-Warning "Provisioning stopped after a write was attempted. No changes were rolled back. Review all requested usernames in tenant '$($TenantId.Guid)' before retrying, including requests whose outcome is unknown."
        foreach ($account in $createdAccounts) {
            Write-Warning "Confirmed user: '$($account.UserPrincipalName)'; object ID: '$($account.Id)'; confirmed Global Administrator assignment ID: '$($account.RoleAssignmentId)'."
        }
    }
}

Write-Warning "Accounts were provisioned, not validated for emergency use. Register phishing-resistant MFA, review Conditional Access exclusions, configure alerts, and test both accounts before enabling restrictive policies."
$createdAccounts.ToArray()
