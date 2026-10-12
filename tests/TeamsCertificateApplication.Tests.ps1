#Requires -Version 7.2

$ErrorActionPreference = "Stop"
$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"

function Get-TestScriptBlock {
    param([Parameter(Mandatory)][string] $Path)

    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref] $null, [ref] $parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }
    $statements = @($ast.EndBlock.Statements | Where-Object {
        $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
        $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
        $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
    })
    [scriptblock]::Create(
        ($ast.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
        $ast.ParamBlock.Extent.Text + "`n" + ($statements.Extent.Text -join "`n")
    )
}

$script:setupPath = Join-Path $scriptsRoot "06-New-TeamsCertificateApplication.ps1"
$script:diagnosticPath = Join-Path $scriptsRoot "07-Test-TeamsCertificateApplication.ps1"
$script:teardownPath = Join-Path $scriptsRoot "08-Remove-TeamsCertificateApplication.ps1"
$script:setupScript = Get-TestScriptBlock $script:setupPath
$script:diagnosticScript = Get-TestScriptBlock $script:diagnosticPath
$script:teardownScript = Get-TestScriptBlock $script:teardownPath

$commonSource = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $scriptsRoot "SecureM365.Common.psm1"), [ref] $null, [ref] $null
)
foreach ($statement in $commonSource.EndBlock.Statements) {
    if (
        $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $statement.Name -in @("Connect-SecureM365Teams", "Get-SecureM365TeamsMeetingPolicy")
    ) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}

function Connect-SecureM365Graph {
    param(
        [guid] $TenantId,
        [string[]] $AdditionalScopes,
        [switch] $UseDeviceCode,
        [switch] $UseBrowserPkce
    )
    [pscustomobject]@{ TenantId = $TenantId.Guid; AuthType = "Delegated" }
}
function Get-SecureM365GraphCollection {
    param([string] $Uri)
    @()
}
function Connect-MicrosoftTeams {
    [CmdletBinding()]
    param(
        [string] $TenantId,
        [switch] $UseDeviceAuthentication,
        [string] $ApplicationId,
        [string] $CertificateThumbprint,
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )
    throw "Unmocked Teams connection."
}
function Disconnect-MicrosoftTeams { [CmdletBinding()] param() throw "Unmocked Teams disconnect." }
function Get-CsTeamsMeetingPolicy {
    [CmdletBinding()]
    param([string] $Identity)
    throw "Unmocked meeting policy read."
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, [string] $Body, [string] $ContentType)
    throw "Unmocked Graph request."
}
function New-SelfSignedCertificate {
    param(
        [string] $Subject,
        [string] $CertStoreLocation,
        [string] $KeyAlgorithm,
        [int] $KeyLength,
        [string] $HashAlgorithm,
        [string] $KeyExportPolicy,
        [string] $KeySpec,
        [datetime] $NotAfter
    )
    throw "Certificate creation was not expected."
}

Describe "Teams certificate application lifecycle (offline)" {
    BeforeEach {
        $script:tenantId = "11111111-1111-4111-8111-111111111111"
        $script:applicationId = "55555555-5555-4555-8555-555555555555"
        $script:existingApplication = $false
        $script:graphWrites = [System.Collections.Generic.List[object]]::new()

        Mock Connect-SecureM365Graph {
            param($TenantId, $AdditionalScopes, $UseDeviceCode, $UseBrowserPkce)
            [pscustomobject]@{ TenantId = $TenantId.Guid; AuthType = "Delegated" }
        }
        Mock Get-ChildItem { @() }
        Mock New-SelfSignedCertificate { throw "Certificate creation was not expected." }
        Mock Remove-Item { throw "Certificate removal was not expected." }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Body, $ContentType)
            [void] $script:graphWrites.Add([pscustomobject]@{
                Method = $Method
                Uri = [string] $Uri
                Body = [string] $Body
            })
        }
        Mock Get-SecureM365GraphCollection {
            param($Uri)
            if ($Uri -like "*/organization?*") {
                return [pscustomobject]@{ id = $script:tenantId; displayName = "Fixture tenant" }
            }
            if ($Uri -like "*/applications?*" -and $script:existingApplication) {
                return [pscustomobject]@{
                    id = "66666666-6666-4666-8666-666666666666"
                    appId = $script:applicationId
                    displayName = "SecureM365 Teams Meeting Policy Automation"
                }
            }
            if ($Uri -like "*/servicePrincipals?*00000003-0000-0000-c000-000000000000*") {
                return [pscustomobject]@{
                    id = "77777777-7777-4777-8777-777777777777"
                    appId = "00000003-0000-0000-c000-000000000000"
                    appRoles = @(
                        [pscustomobject]@{
                            id = "88888888-8888-4888-8888-888888888888"
                            value = "Organization.Read.All"
                            allowedMemberTypes = @("Application")
                        }
                    )
                }
            }
            if ($Uri -like "*/roleManagement/directory/roleDefinitions?*") {
                return [pscustomobject]@{
                    id = "99999999-9999-4999-8999-999999999999"
                    templateId = "baf37b3a-610e-45da-9e62-d9d1e5e8914b"
                    displayName = "Teams Communications Administrator"
                    isBuiltIn = $true
                }
            }
            @()
        }
    }

    It "makes no tenant or certificate mutations under WhatIf" {
        $result = & $script:setupScript `
            -TenantId $script:tenantId `
            -WhatIf `
            -Confirm:$false

        $result.GraphApplicationPermission | Should Be "Organization.Read.All"
        $result.DirectoryRole | Should Be "Teams Communications Administrator"
        $script:graphWrites.Count | Should Be 0
        Assert-MockCalled New-SelfSignedCertificate -Times 0
    }

    It "refuses an existing application collision before any mutation" {
        $script:existingApplication = $true

        {
            & $script:setupScript -TenantId $script:tenantId -Confirm:$false
        } | Should Throw "refuses collisions"

        $script:graphWrites.Count | Should Be 0
        Assert-MockCalled New-SelfSignedCertificate -Times 0
    }

    It "makes no revocation or certificate mutation under WhatIf" {
        $script:existingApplication = $true

        $result = & $script:teardownScript `
            -TenantId $script:tenantId `
            -ApplicationId $script:applicationId `
            -CertificateThumbprint "0123456789ABCDEF0123456789ABCDEF01234567" `
            -RemoveLocalCertificate `
            -WhatIf `
            -Confirm:$false

        $result.ApplicationFound | Should Be $true
        $script:graphWrites.Count | Should Be 0
        Assert-MockCalled Remove-Item -Times 0
    }

    It "does not emit or document private key material" {
        $setupSource = Get-Content $script:setupPath -Raw
        $teardownSource = Get-Content $script:teardownPath -Raw
        $ignore = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) ".gitignore")
        $setupSource | Should Match "KeyExportPolicy NonExportable"
        $setupSource | Should Not Match '(?i)Export-PfxCertificate|ConvertFrom-SecureString|clientSecret|password\s*='
        $teardownSource | Should Not Match '(?i)ConvertFrom-SecureString|clientSecret|privateKey'
        foreach ($pattern in @("*.pfx", "*.p12", "*.pem", "*.key")) {
            ($ignore -contains $pattern) | Should Be $true
        }
    }

    It "wires certificate parameters through every Teams caller" {
        foreach ($name in @(
            "01-Test-TenantConnections.ps1",
            "05-Verify-Admin-Permissions.ps1",
            "40-Set-TeamsInvitedUsersLobbyPolicy.ps1",
            "41-Test-TeamsInvitedUsersLobbyPolicy.ps1",
            "42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1",
            "43-Test-TeamsOrganizerOnlyPresenterPolicy.ps1",
            "44-Disable-TeamsAnonymousMeetingJoin.ps1",
            "45-Test-TeamsAnonymousMeetingJoin.ps1",
            "99-Test-M365RecommendationStatus.ps1"
        )) {
            $source = Get-Content (Join-Path $scriptsRoot $name) -Raw
            $source | Should Match '\$TeamsApplicationId'
            $source | Should Match '\$TeamsCertificateThumbprint'
            $source | Should Match '\$TeamsCertificatePath'
        }
    }
}

Describe "Teams certificate application diagnostic (offline)" {
    BeforeEach {
        $script:diagnosticParameters = @{
            TenantId = [guid] "11111111-1111-4111-8111-111111111111"
            ApplicationId = [guid] "55555555-5555-4555-8555-555555555555"
            CertificateThumbprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        }
        $script:connectedTenantId = $script:diagnosticParameters.TenantId.Guid
        $script:diagnosticCertificates = @(
            [pscustomobject]@{
                Thumbprint = $script:diagnosticParameters.CertificateThumbprint
                HasPrivateKey = $true
                NotBefore = (Get-Date).AddDays(-1)
                NotAfter = (Get-Date).AddMonths(12)
            }
        )
        $script:diagnosticPolicies = @([pscustomobject]@{ Identity = "Global" })

        Mock Get-ChildItem { $script:diagnosticCertificates }
        Mock Connect-MicrosoftTeams {
            [pscustomobject]@{ TenantId = $script:connectedTenantId }
        }
        Mock Disconnect-MicrosoftTeams {}
        Mock Get-CsTeamsMeetingPolicy { $script:diagnosticPolicies }
        Mock Connect-SecureM365Graph { throw "Delegated Graph sign-in is not allowed." }
        Mock Invoke-MgGraphRequest { throw "Graph requests are not allowed." }
    }

    It "passes only after explicit app authentication and exactly one Global policy read" {
        $results = @(& $script:diagnosticScript @script:diagnosticParameters)

        $results.Count | Should Be 1
        $result = $results[0]
        $result.Status | Should Be "PASSED"
        $result.TenantId | Should Be $script:diagnosticParameters.TenantId.Guid
        $result.ApplicationId | Should Be $script:diagnosticParameters.ApplicationId.Guid
        $result.AuthenticationType | Should Be "AppOnly"
        $result.CertificateSource | Should Be "Cert:\CurrentUser\My\$($script:diagnosticParameters.CertificateThumbprint)"
        $result.PolicyIdentity | Should Be "Global"
        $result.MeetingPolicyAccessVerified | Should Be $true
        ([DateTimeOffset]::Parse($result.CheckedAt).Offset) | Should Be ([timespan]::Zero)
        Assert-MockCalled Get-ChildItem -Times 1 -Exactly -Scope It -ParameterFilter {
            $Path -eq "Cert:\CurrentUser\My"
        }
        Assert-MockCalled Connect-MicrosoftTeams -Times 1 -Exactly -Scope It -ParameterFilter {
            $TenantId -eq $script:diagnosticParameters.TenantId.Guid -and
            $ApplicationId -eq $script:diagnosticParameters.ApplicationId.Guid -and
            $CertificateThumbprint -eq $script:diagnosticParameters.CertificateThumbprint -and
            -not $UseDeviceAuthentication
        }
        Assert-MockCalled Get-CsTeamsMeetingPolicy -Times 1 -Exactly -Scope It -ParameterFilter {
            $Identity -eq "Global"
        }
        Assert-MockCalled Connect-SecureM365Graph -Times 0 -Scope It
        Assert-MockCalled Invoke-MgGraphRequest -Times 0 -Scope It
    }

    It "normalizes whitespace and lowercase in the supplied thumbprint" {
        $script:diagnosticParameters.CertificateThumbprint = "01234567 89abcdef 01234567 89abcdef 01234567"

        $result = & $script:diagnosticScript @script:diagnosticParameters

        $result.CertificateSource | Should Be "Cert:\CurrentUser\My\0123456789ABCDEF0123456789ABCDEF01234567"
        Assert-MockCalled Connect-MicrosoftTeams -Times 1 -Exactly -Scope It -ParameterFilter {
            $CertificateThumbprint -ceq "0123456789ABCDEF0123456789ABCDEF01234567"
        }
    }

    It "explains the original-user and original-machine requirement when the certificate is absent" {
        $script:diagnosticCertificates = @()

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "non-exportable private key"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "refuses ambiguous local certificate matches" {
        $script:diagnosticCertificates += $script:diagnosticCertificates[0].PSObject.Copy()

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "found 2"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects a public-only certificate before authentication" {
        $script:diagnosticCertificates[0].HasPrivateKey = $false

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "no private key"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects an expired certificate before authentication" {
        $script:diagnosticCertificates[0].NotAfter = (Get-Date).AddSeconds(-1)

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "expired"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects a certificate that is not yet valid before authentication" {
        $script:diagnosticCertificates[0].NotBefore = (Get-Date).AddHours(1)

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "not valid until"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects malformed thumbprint '<Value>' without accessing the store" -TestCases @(
        @{ Value = "not-a-thumbprint" }
        @{ Value = "01234567" }
        @{ Value = "*" }
        @{ Value = "   " }
    ) {
        param($Value)
        $script:diagnosticParameters.CertificateThumbprint = $Value

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "hexadecimal"

        Assert-MockCalled Get-ChildItem -Times 0 -Scope It
        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects an empty <Name> before any connection" -TestCases @(
        @{ Name = "TenantId" }
        @{ Name = "ApplicationId" }
    ) {
        param($Name)
        $script:diagnosticParameters[$Name] = [guid]::Empty

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "validation script"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "fails and disconnects rather than trusting an unexpected tenant" -TestCases @(
        @{ Tenant = "99999999-9999-4999-8999-999999999999" }
        @{ Tenant = $null }
    ) {
        param($Tenant)
        $script:connectedTenantId = $Tenant

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "instead of"

        Assert-MockCalled Disconnect-MicrosoftTeams -Times 1 -Exactly -Scope It
        Assert-MockCalled Get-CsTeamsMeetingPolicy -Times 0 -Scope It
    }

    It "propagates authentication errors without falling back to a user sign-in" {
        Mock Connect-MicrosoftTeams { throw "Fixture certificate authentication failed." }

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "Fixture certificate authentication failed"

        Assert-MockCalled Connect-MicrosoftTeams -Times 1 -Exactly -Scope It -ParameterFilter {
            $ApplicationId -eq $script:diagnosticParameters.ApplicationId.Guid -and
            -not $UseDeviceAuthentication
        }
        Assert-MockCalled Get-CsTeamsMeetingPolicy -Times 0 -Scope It
        Assert-MockCalled Connect-SecureM365Graph -Times 0 -Scope It
    }

    It "does not treat authentication alone as proof of meeting-policy access" {
        Mock Get-CsTeamsMeetingPolicy { throw "Forbidden fixture response." }

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "Forbidden fixture response"

        Assert-MockCalled Get-CsTeamsMeetingPolicy -Times 1 -Exactly -Scope It
    }

    It "rejects <Mode> meeting-policy results" -TestCases @(
        @{ Mode = "empty"; Message = "returned 0" }
        @{ Mode = "multiple"; Message = "returned 2" }
        @{ Mode = "wrong identity"; Message = "when Global was requested" }
    ) {
        param($Mode, $Message)
        switch ($Mode) {
            "empty" { $script:diagnosticPolicies = @() }
            "multiple" { $script:diagnosticPolicies += [pscustomobject]@{ Identity = "Global" } }
            "wrong identity" { $script:diagnosticPolicies[0].Identity = "Tag:Custom" }
        }

        { & $script:diagnosticScript @script:diagnosticParameters } | Should Throw $Message
    }

    It "routes an approved PFX and SecureString to the shared functional validator" {
        $script:diagnosticParameters.Remove("CertificateThumbprint")
        $script:diagnosticParameters.CertificatePath = "C:\SecureM365Keys\fixture.pfx"
        $script:diagnosticParameters.CertificatePassword = [securestring]::new()
        Mock Connect-SecureM365Teams {
            [pscustomobject]@{ TenantId = $script:connectedTenantId }
        } -ParameterFilter {
            $CertificatePath -eq "C:\SecureM365Keys\fixture.pfx" -and
            [string]::IsNullOrEmpty($CertificateThumbprint)
        }

        $result = & $script:diagnosticScript @script:diagnosticParameters

        $result.Status | Should Be "PASSED"
        $result.CertificateSource | Should Be $script:diagnosticParameters.CertificatePath
        Assert-MockCalled Connect-SecureM365Teams -Times 1 -Exactly -Scope It -ParameterFilter {
            $TenantId -eq $script:diagnosticParameters.TenantId -and
            $ApplicationId -eq $script:diagnosticParameters.ApplicationId -and
            $CertificatePath -eq $script:diagnosticParameters.CertificatePath -and
            $CertificatePassword -eq $script:diagnosticParameters.CertificatePassword -and
            $ValidateMeetingPolicyAccess -and
            [string]::IsNullOrEmpty($CertificateThumbprint)
        }
        Assert-MockCalled Get-ChildItem -Times 0 -Scope It
    }

    It "fails before authentication for a missing PFX" {
        $script:diagnosticParameters.Remove("CertificateThumbprint")
        $script:diagnosticParameters.CertificatePath = Join-Path $TestDrive "missing.pfx"

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "does not exist"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "preserves the shared rejection of certificate paths inside the repository" {
        $script:diagnosticParameters.Remove("CertificateThumbprint")
        $script:diagnosticParameters.CertificatePath = $script:diagnosticPath

        # This guard needs the module's real PSScriptRoot, not a fileless AST copy.
        $module = Import-Module (Join-Path $scriptsRoot "SecureM365.Common.psm1") `
            -Prefix CertificateTest -Force -PassThru
        try {
            {
                & $module {
                    param($Parameters)
                    Connect-SecureM365Teams @Parameters
                } $script:diagnosticParameters
            } | Should Throw "outside the repository"
        }
        finally {
            Remove-Module -ModuleInfo $module -Force
        }

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects a PFX path combined with a thumbprint" {
        $script:diagnosticParameters.CertificatePath = "C:\SecureM365Keys\fixture.pfx"

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "Parameter set cannot be resolved"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "rejects a PFX password combined with a thumbprint" {
        $script:diagnosticParameters.CertificatePassword = [securestring]::new()

        { & $script:diagnosticScript @script:diagnosticParameters } |
            Should Throw "Parameter set cannot be resolved"

        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Scope It
    }

    It "requires only MicrosoftTeams and contains no tenant or certificate write commands" {
        $source = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:diagnosticPath, [ref] $null, [ref] $null
        )
        $source.ScriptRequirements.RequiredModules.Count | Should Be 1
        $source.ScriptRequirements.RequiredModules[0].Name | Should Be "MicrosoftTeams"
        $commands = @($source.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($name in @(
            "Connect-SecureM365Graph", "Connect-MgGraph", "Invoke-MgGraphRequest",
            "New-SelfSignedCertificate", "Export-PfxCertificate", "Import-PfxCertificate",
            "Set-CsTeamsMeetingPolicy", "Remove-Item"
        )) {
            ($commands -contains $name) | Should Be $false
        }
    }
}
