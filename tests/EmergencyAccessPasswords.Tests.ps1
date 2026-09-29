#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$scriptPath = Join-Path $scriptsRoot "04-New-EmergencyAccessAccounts.ps1"
$parseErrors = $null
$scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref] $null, [ref] $parseErrors
)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }

foreach ($statement in $scriptAst.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
$scriptStatements = @($scriptAst.EndBlock.Statements | Where-Object {
    $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
    $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
    $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
})
$scriptUnderTest = [scriptblock]::Create(
    ($scriptAst.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
    $scriptAst.ParamBlock.Extent.Text + "`n" + ($scriptStatements.Extent.Text -join "`n")
)

function Connect-SecureM365Graph {
    param([guid] $TenantId, [string[]] $AdditionalScopes, [switch] $UseDeviceCode)
}
function Get-SecureM365GraphCollection {
    param([string] $Uri)

    if ($Uri -like "*v1.0/domains*") {
        return [pscustomobject]@{
            id = "contoso.onmicrosoft.com"
            isInitial = $true
            isVerified = $true
            authenticationType = "Managed"
        }
    }
    if ($Uri -like "*roleDefinitions*") {
        return [pscustomobject]@{
            id = "22222222-2222-4222-8222-222222222222"
            templateId = "62e90394-69f5-4237-9190-012177145e10"
            isBuiltIn = $true
        }
    }
    @()
}
function Invoke-MgGraphRequest {
    param(
        [string] $Method,
        [string] $Uri,
        [string] $Body,
        [string] $ContentType
    )

    if ($Uri -like "*/users") {
        if (-not (Test-Path -LiteralPath $script:expectedArtifactPath)) {
            throw "The password artifact was not persisted before the first tenant write."
        }
        $script:firstWriteSawArtifact = $true
        $persisted = Get-Content -LiteralPath $script:expectedArtifactPath -Raw |
            ConvertFrom-Json
        @($persisted.accounts).Count | Should Be 2
        $request = $Body | ConvertFrom-Json
        $id = if ($request.mailNickname -like "*01") {
            "33333333-3333-4333-8333-333333333333"
        }
        else {
            "44444444-4444-4444-8444-444444444444"
        }
        return [pscustomobject]@{
            id = $id
            userPrincipalName = $request.userPrincipalName
        }
    }

    $request = $Body | ConvertFrom-Json
    [pscustomobject]@{
        id = [guid]::NewGuid().Guid
        principalId = $request.principalId
        roleDefinitionId = $request.roleDefinitionId
        directoryScopeId = $request.directoryScopeId
    }
}

Describe "Emergency access password protection (offline)" {
    It "generates distinct strong printable passwords" {
        $passwords = @()
        $plainPasswords = @()
        try {
            1..20 | ForEach-Object {
                $password = New-EmergencyPassword
                $passwords += $password
                $plain = [System.Net.NetworkCredential]::new("", $password).Password
                $plainPasswords += $plain

                $plain.Length | Should Be 48
                $plain | Should Match '[a-z]'
                $plain | Should Match '[A-Z]'
                $plain | Should Match '[0-9]'
                $plain | Should Match '[^a-zA-Z0-9]'
                $plain | Should Not Match '[^\x20-\x7E]'
            }
            @($plainPasswords | Sort-Object -Unique).Count | Should Be 20
        }
        finally {
            $plain = $null
            $plainPasswords = $null
            foreach ($password in $passwords) {
                $password.Dispose()
            }
        }
    }

    It "persists tenant and UPN metadata with recoverable DPAPI ciphertext" {
        $tenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $path = Join-Path $TestDrive "emergency-passwords.json"
        $passwords = @{}
        $fingerprints = @{}
        try {
            foreach ($upn in @(
                "emergency-01@contoso.onmicrosoft.com"
                "emergency-02@contoso.onmicrosoft.com"
            )) {
                $passwords[$upn] = New-EmergencyPassword
                $fingerprints[$upn] = Get-SecurePasswordFingerprint $passwords[$upn]
            }

            Save-EmergencyPasswordArtifact `
                -ArtifactTenantId $tenantId `
                -Passwords $passwords `
                -Fingerprints $fingerprints `
                -Path $path

            $artifact = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $artifact.schemaVersion | Should Be 1
            $artifact.protection | Should Be "WindowsUserDpapiSecureString"
            $artifact.tenantId | Should Be $tenantId.Guid
            @($artifact.accounts).Count | Should Be 2
            foreach ($entry in $artifact.accounts) {
                $recovered = ConvertTo-SecureString $entry.encryptedPassword
                try {
                    (Get-SecurePasswordFingerprint $recovered) |
                        Should Be $fingerprints[$entry.userPrincipalName]
                }
                finally {
                    $recovered.Dispose()
                }
            }

            $overwriteError = $null
            try {
                Save-EmergencyPasswordArtifact `
                    -ArtifactTenantId $tenantId `
                    -Passwords $passwords `
                    -Fingerprints $fingerprints `
                    -Path $path
            }
            catch {
                $overwriteError = $_
            }
            $overwriteError | Should Not BeNullOrEmpty
            $overwriteError.Exception.Message | Should Match "already exists"
        }
        finally {
            foreach ($password in $passwords.Values) {
                $password.Dispose()
            }
        }
    }

    It "does not create a password file under WhatIf" {
        $path = Join-Path $TestDrive "whatif-passwords.json"

        & $scriptUnderTest `
            -TenantId "11111111-1111-4111-8111-111111111111" `
            -PasswordFilePath $path `
            -WhatIf `
            -Confirm:$false |
            Out-Null

        Test-Path -LiteralPath $path | Should Be $false
    }

    It "persists and verifies every password before the first tenant write" {
        $script:expectedArtifactPath = Join-Path $TestDrive "before-write-passwords.json"
        $script:firstWriteSawArtifact = $false

        $accounts = @(
            & $scriptUnderTest `
                -TenantId "11111111-1111-4111-8111-111111111111" `
                -PasswordFilePath $script:expectedArtifactPath `
                -Confirm:$false `
                3>$null
        )

        $script:firstWriteSawArtifact | Should Be $true
        $accounts.Count | Should Be 2
        $accounts.RoleAssignmentId | Should Not BeNullOrEmpty
        $artifact = Get-Content -LiteralPath $script:expectedArtifactPath -Raw |
            ConvertFrom-Json
        @($artifact.accounts.userPrincipalName | Sort-Object) | Should Be @(
            "emergency-access-01@contoso.onmicrosoft.com"
            "emergency-access-02@contoso.onmicrosoft.com"
        )
    }
}
