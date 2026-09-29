#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Creates cloud-only emergency access accounts with permanent Global Administrator access.

.DESCRIPTION
Uses the tenant's initial, verified, managed onmicrosoft.com domain. Checks every
requested username before making changes and refuses to modify existing users.
Generates distinct 48-character cryptographically random printable passwords with
all four character categories. Before creating any tenant object, saves each
password with tenant and UPN metadata in a Windows user-scoped DPAPI-encrypted
JSON file and verifies that every entry can be recovered. WhatIf performs
discovery without requesting write scopes, generating passwords, or creating a file.

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

.PARAMETER PasswordFilePath
Path for the DPAPI-encrypted credential artifact. The default is a tenant-specific
file under Documents\SecureM365. The file can be decrypted only by the same
Windows user on the same computer.

.PARAMETER OverwritePasswordFile
Explicitly replace an existing password file. Without this switch, the script
refuses to overwrite the path.

.EXAMPLE
.\04-New-EmergencyAccessAccounts.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
$accounts = @(.\04-New-EmergencyAccessAccounts.ps1 -TenantId $TenantId)
$accounts | Select-Object Id, UserPrincipalName, RoleAssignmentId

.EXAMPLE
$artifact = Get-Content "$HOME\Documents\SecureM365\EmergencyAccessPasswords-$TenantId.json" -Raw |
    ConvertFrom-Json
$credential = $artifact.accounts[0]
$securePassword = ConvertTo-SecureString $credential.encryptedPassword
$plainPassword = [System.Net.NetworkCredential]::new("", $securePassword).Password
# Use the password, then clear the variables and dispose the secure string.
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

    [switch] $UseDeviceCode,

    [string] $PasswordFilePath,

    [switch] $OverwritePasswordFile
)

$ErrorActionPreference = "Stop"

if ($TenantId -eq [guid]::Empty) {
    throw "Supply a nonempty Microsoft Entra tenant GUID."
}
if (@($AccountName | Sort-Object -Unique).Count -ne $AccountName.Count) {
    throw "Supply at least two distinct account names; names are not case-sensitive."
}
if (-not $IsWindows) {
    throw "This script requires Windows because emergency passwords are protected with Windows user-scoped DPAPI."
}
if ([string]::IsNullOrWhiteSpace($PasswordFilePath)) {
    $documentsPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    if ([string]::IsNullOrWhiteSpace($documentsPath)) {
        throw "Could not resolve the current user's Documents folder. Supply PasswordFilePath explicitly."
    }
    $PasswordFilePath = Join-Path `
        (Join-Path $documentsPath "SecureM365") `
        "EmergencyAccessPasswords-$($TenantId.Guid).json"
}
$PasswordFilePath = [IO.Path]::GetFullPath($PasswordFilePath)

function Get-SecurePasswordFingerprint {
    param(
        [Parameter(Mandatory)]
        [securestring] $SecurePassword
    )

    $plainPassword = $null
    $passwordBytes = $null
    try {
        $plainPassword = [System.Net.NetworkCredential]::new("", $SecurePassword).Password
        $passwordBytes = [Text.Encoding]::UTF8.GetBytes($plainPassword)
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($passwordBytes))
    }
    finally {
        if ($null -ne $passwordBytes) {
            [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
        }
        $plainPassword = $null
    }
}

function New-EmergencyPassword {
    [OutputType([securestring])]
    param()

    [string[]] $categories = @(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!#$%&()*+,-./:;<=>?@[]^_{|}~"
    )
    $allCharacters = [char[]] (($categories | ForEach-Object { -join $_ }) -join "")
    $characters = [char[]]::new(48)
    try {
        for ($index = 0; $index -lt $categories.Count; $index++) {
            $characters[$index] = $categories[$index][
                [Security.Cryptography.RandomNumberGenerator]::GetInt32($categories[$index].Count)
            ]
        }
        for ($index = $categories.Count; $index -lt $characters.Count; $index++) {
            $characters[$index] = $allCharacters[
                [Security.Cryptography.RandomNumberGenerator]::GetInt32($allCharacters.Count)
            ]
        }
        for ($index = $characters.Count - 1; $index -gt 0; $index--) {
            $swapIndex = [Security.Cryptography.RandomNumberGenerator]::GetInt32($index + 1)
            ($characters[$index], $characters[$swapIndex]) = (
                $characters[$swapIndex], $characters[$index]
            )
        }

        $securePassword = [securestring]::new()
        foreach ($character in $characters) {
            $securePassword.AppendChar($character)
        }
        $securePassword.MakeReadOnly()
        $securePassword
    }
    finally {
        [Array]::Clear($characters, 0, $characters.Length)
        [Array]::Clear($allCharacters, 0, $allCharacters.Length)
    }
}

function Save-EmergencyPasswordArtifact {
    param(
        [Parameter(Mandatory)]
        [guid] $ArtifactTenantId,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Passwords,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Fingerprints,

        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $Overwrite
    )

    if (Test-Path -LiteralPath $Path -PathType Container) {
        throw "PasswordFilePath '$Path' is a directory. Supply a file path."
    }
    if ((Test-Path -LiteralPath $Path) -and -not $Overwrite) {
        throw "Password file '$Path' already exists. No accounts were created. Use OverwritePasswordFile only after confirming that replacement is intended."
    }

    $directory = [IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrWhiteSpace($directory)) {
        throw "PasswordFilePath must include a parent directory."
    }
    [void] [IO.Directory]::CreateDirectory($directory)

    $temporaryPath = Join-Path $directory ".$([IO.Path]::GetRandomFileName()).tmp"
    try {
        $entries = @(
            foreach ($upn in ($Passwords.Keys | Sort-Object)) {
                [ordered]@{
                    userPrincipalName = $upn
                    encryptedPassword = ConvertFrom-SecureString $Passwords[$upn]
                }
            }
        )
        $artifact = [ordered]@{
            schemaVersion = 1
            protection = "WindowsUserDpapiSecureString"
            tenantId = $ArtifactTenantId.Guid
            createdAtUtc = [DateTimeOffset]::UtcNow.ToString("o")
            accounts = $entries
        }
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($artifact | ConvertTo-Json -Depth 4),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force:$Overwrite

        $persistedArtifact = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if (
            $persistedArtifact.schemaVersion -ne 1 -or
            $persistedArtifact.protection -ne "WindowsUserDpapiSecureString" -or
            $persistedArtifact.tenantId -ne $ArtifactTenantId.Guid -or
            @($persistedArtifact.accounts).Count -ne $Passwords.Count
        ) {
            throw "Password file '$Path' failed metadata verification. No accounts were created."
        }
        foreach ($entry in @($persistedArtifact.accounts)) {
            if (
                [string]::IsNullOrWhiteSpace($entry.userPrincipalName) -or
                -not $Passwords.Contains($entry.userPrincipalName) -or
                [string]::IsNullOrWhiteSpace($entry.encryptedPassword)
            ) {
                throw "Password file '$Path' contains an unexpected or incomplete account entry. No accounts were created."
            }
            $recoveredPassword = $null
            try {
                $recoveredPassword = ConvertTo-SecureString $entry.encryptedPassword
                if (
                    (Get-SecurePasswordFingerprint $recoveredPassword) -ne
                    $Fingerprints[$entry.userPrincipalName]
                ) {
                    throw "Password file '$Path' failed recovery verification for '$($entry.userPrincipalName)'. No accounts were created."
                }
            }
            finally {
                if ($null -ne $recoveredPassword) {
                    $recoveredPassword.Dispose()
                }
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
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

$passwords = @{}
$passwordFingerprints = @{}
$createdAccounts = [System.Collections.Generic.List[object]]::new()
$creationAttempted = $false
$completed = $false

try {
    # Generate and persist every password before the first tenant write.
    foreach ($account in $plannedAccounts) {
        $upn = $account.UserPrincipalName
        do {
            if ($passwords.Contains($upn)) {
                $passwords[$upn].Dispose()
            }
            $passwords[$upn] = New-EmergencyPassword
            $passwordFingerprints[$upn] = Get-SecurePasswordFingerprint $passwords[$upn]
        } while (
            @($passwordFingerprints.GetEnumerator() | Where-Object {
                $_.Key -ne $upn -and $_.Value -eq $passwordFingerprints[$upn]
            }).Count -gt 0
        )
    }

    Save-EmergencyPasswordArtifact `
        -ArtifactTenantId $TenantId `
        -Passwords $passwords `
        -Fingerprints $passwordFingerprints `
        -Path $PasswordFilePath `
        -Overwrite:$OverwritePasswordFile
    Write-Warning "Emergency passwords were saved to '$PasswordFilePath' with Windows user-scoped DPAPI protection. Copy the file to an approved protected backup; only this Windows user on this computer can decrypt it."

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
    $passwords.Clear()
    $passwordFingerprints.Clear()
    if ($creationAttempted -and -not $completed) {
        Write-Warning "Provisioning stopped after a write was attempted. No changes were rolled back. Review all requested usernames in tenant '$($TenantId.Guid)' before retrying, including requests whose outcome is unknown."
        foreach ($account in $createdAccounts) {
            Write-Warning "Confirmed user: '$($account.UserPrincipalName)'; object ID: '$($account.Id)'; confirmed Global Administrator assignment ID: '$($account.RoleAssignmentId)'."
        }
    }
}

Write-Warning "Accounts were provisioned, not validated for emergency use. Register phishing-resistant MFA, review Conditional Access exclusions, configure alerts, and test both accounts before enabling restrictive policies."
$createdAccounts.ToArray()
