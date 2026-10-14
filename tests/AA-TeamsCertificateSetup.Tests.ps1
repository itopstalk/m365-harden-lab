#Requires -Version 7.2

$ErrorActionPreference = "Stop"
$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$scriptPath = Join-Path $scriptsRoot "AA-AssessM365Status.ps1"
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref] $null, [ref] $parseErrors
)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }
foreach ($statement in $ast.EndBlock.Statements) {
    if (
        $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $statement.Name -in @(
            "ConvertTo-SecureM365ObjectId", "Test-SecureM365Property",
            "Assert-SecureM365TeamsCertificate", "Get-SecureM365TeamsApplicationPlan",
            "New-SecureM365TeamsApplication", "Connect-SecureM365AssessmentTeams",
            "Connect-SecureM365Teams", "Get-SecureM365TeamsMeetingPolicy",
            "Get-SecureM365GraphScopeSet"
        )
    ) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}

function Connect-SecureM365Graph {
    [CmdletBinding()]
    param([guid] $TenantId, [string[]] $AdditionalScopes, [switch] $UseDeviceCode, [switch] $UseBrowserPkce)
    throw "Unmocked Graph connection."
}
function Get-SecureM365GraphCollection {
    param([string] $Uri)
    throw "Unmocked Graph collection."
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, [string] $Body, [string] $ContentType)
    throw "Unmocked Graph request."
}
function Get-MgContext { [CmdletBinding()] param() throw "Unmocked Graph context." }
function Connect-MgGraph { [CmdletBinding()] param() throw "Unmocked Graph sign-in." }
function Connect-MicrosoftTeams {
    [CmdletBinding()]
    param(
        [string] $TenantId, [string] $ApplicationId, [string] $CertificateThumbprint,
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [switch] $UseDeviceAuthentication
    )
    throw "Unmocked Teams connection."
}
function Disconnect-MicrosoftTeams { [CmdletBinding()] param() throw "Unmocked Teams disconnect." }
function Get-CsTeamsMeetingPolicy {
    [CmdletBinding()]
    param([string] $Identity)
    throw "Unmocked Teams policy read."
}
function New-SelfSignedCertificate {
    [CmdletBinding()]
    param(
        [string] $Subject, [string] $CertStoreLocation, [string] $KeyAlgorithm,
        [int] $KeyLength, [string] $HashAlgorithm, [string] $KeyExportPolicy,
        [string] $KeySpec, [datetime] $NotAfter
    )
    throw "Unmocked certificate creation."
}
function Get-Module {
    [CmdletBinding()]
    param([string[]] $Name, [switch] $ListAvailable)
    throw "Unmocked module discovery."
}
function Install-Module {
    [CmdletBinding()]
    param([string[]] $Name, [string] $Scope, [string[]] $Repository)
    throw "Unmocked module installation."
}

function New-MemoryTestCertificate {
    param(
        [string] $Subject,
        [int] $KeySize = 3072,
        [datetimeoffset] $NotAfter = [datetimeoffset]::UtcNow.AddMonths(12)
    )
    $rsa = [Security.Cryptography.RSA]::Create($KeySize)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddYears(-1), $NotAfter)
    }
    finally {
        $rsa.Dispose()
    }
}

Describe "AA automatic Teams certificate lifecycle (offline)" {
    BeforeEach {
        $script:fixture = @{
            TenantId = [guid] "11111111-1111-4111-8111-111111111111"
            ApplicationId = "55555555-5555-4555-8555-555555555555"
            ApplicationObjectId = "66666666-6666-4666-8666-666666666666"
            PrincipalId = "22222222-2222-4222-8222-222222222222"
            GraphPrincipalId = "77777777-7777-4777-8777-777777777777"
            OrganizationRoleId = "88888888-8888-4888-8888-888888888888"
            TeamsRoleId = "99999999-9999-4999-8999-999999999999"
            Applications = @()
            Certificates = @()
            Principals = @()
            AppGrants = @()
            DirectoryGrants = @()
            Writes = [Collections.Generic.List[object]]::new()
            WriteScopes = @()
            FailWrite = ""
            PolicyFailures = 0
            PolicyReads = 0
            DuplicateRole = $false
            NewCertificate = $null
            StoredCertificate = $null
        }
        $script:fixture.Subject = "CN=SecureM365 Teams Assessment $($script:fixture.TenantId.Guid)"
        $script:parameters = @{
            TenantId = $script:fixture.TenantId
            GraphParameters = @{
                TenantId = $script:fixture.TenantId
                AdditionalScopes = @("Application.Read.All", "Organization.Read.All")
                UseBrowserPkce = $true
            }
        }
        Mock Get-ChildItem { $script:fixture.Certificates } -ParameterFilter {
            $Path -eq "Cert:\CurrentUser\My"
        }
        Mock Assert-SecureM365TeamsCertificate {}
        Mock New-SelfSignedCertificate {
            $script:fixture.NewCertificate = New-MemoryTestCertificate -Subject $Subject
            $script:fixture.StoredCertificate =
                [Security.Cryptography.X509Certificates.X509Certificate2]::new($script:fixture.NewCertificate)
            $script:fixture.Certificates = @($script:fixture.StoredCertificate)
            $script:fixture.NewCertificate
        }
        Mock Connect-SecureM365Graph {
            $script:fixture.WriteScopes = @($AdditionalScopes)
            [pscustomobject]@{ TenantId = $TenantId.Guid; AuthType = "Delegated"; Environment = "Global" }
        }
        Mock Get-SecureM365GraphCollection {
            if ($Uri -like "*/servicePrincipals?*00000003-0000-0000-c000-000000000000*") {
                return @{
                    id = $script:fixture.GraphPrincipalId
                    appId = "00000003-0000-0000-c000-000000000000"
                    appRoles = @(@{
                        id = $script:fixture.OrganizationRoleId
                        value = "Organization.Read.All"
                        allowedMemberTypes = @("Application")
                        isEnabled = $true
                    })
                }
            }
            if ($Uri -like "*/roleDefinitions?*") {
                $role = @{
                    id = $script:fixture.TeamsRoleId
                    templateId = "baf37b3a-610e-45da-9e62-d9d1e5e8914b"
                    displayName = "Teams Communications Administrator"
                    isBuiltIn = $true
                }
                if ($script:fixture.DuplicateRole) { return @($role, $role) }
                return $role
            }
            if ($Uri -match "/applications\?") { return $script:fixture.Applications }
            if ($Uri -match "/servicePrincipals\?") { return $script:fixture.Principals }
            if ($Uri -like "*/appRoleAssignments") { return $script:fixture.AppGrants }
            if ($Uri -like "*/roleAssignments?*") { return $script:fixture.DirectoryGrants }
            throw "Unexpected fixture collection: $Uri"
        }
        Mock Invoke-MgGraphRequest {
            if ($Method -eq "GET" -and $Uri -like "*/applications/*") {
                return $script:fixture.Application
            }
            if ($Method -ne "POST") { throw "Unexpected Graph mutation: $Method $Uri" }
            $data = $Body | ConvertFrom-Json -AsHashtable
            $script:fixture.Writes.Add(@{ Uri = $Uri; Body = $data })
            if ($script:fixture.FailWrite -and $Uri -like "*$($script:fixture.FailWrite)") {
                throw "Fixture Graph write failed."
            }
            if ($Uri -eq "https://graph.microsoft.com/v1.0/applications") {
                $data.id = $script:fixture.ApplicationObjectId
                $data.appId = $script:fixture.ApplicationId
                $data.passwordCredentials = @()
                $script:fixture.Application = $data
                $script:fixture.Applications = @($data)
                return $data
            }
            if ($Uri -eq "https://graph.microsoft.com/v1.0/servicePrincipals") {
                $data.id = $script:fixture.PrincipalId
                $data.accountEnabled = $true
                $data.passwordCredentials = @()
                $script:fixture.Principals = @($data)
                return $data
            }
            if ($Uri -like "*/appRoleAssignments") {
                $data.id = "fixture-app-grant"
                $script:fixture.AppGrants = @($data)
                return $data
            }
            if ($Uri -eq "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments") {
                $data.id = "fixture-directory-grant"
                $script:fixture.DirectoryGrants = @($data)
                return $data
            }
            throw "Unexpected Graph write: $Uri"
        }
        Mock Connect-MicrosoftTeams {
            [pscustomobject]@{ TenantId = $TenantId; Account = $ApplicationId }
        }
        Mock Get-CsTeamsMeetingPolicy {
            $script:fixture.PolicyReads++
            if ($script:fixture.PolicyReads -le $script:fixture.PolicyFailures) {
                throw "Forbidden: fixture policy access denied."
            }
            [pscustomobject]@{ Identity = "Global" }
        }
        Mock Disconnect-MicrosoftTeams {}
        Mock Start-Sleep {}
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Remove-Item { throw "Automatic cleanup must not remove certificates." }
    }

    AfterEach {
        if ($null -ne $script:fixture.NewCertificate) { $script:fixture.NewCertificate.Dispose() }
        if ($null -ne $script:fixture.StoredCertificate) { $script:fixture.StoredCertificate.Dispose() }
    }

    It "provisions only the AA identity and approved grants, then validates certificate access" {
        $output = @(Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false)

        $output.Count | Should Be 1
        $output[0].Account | Should Be $script:fixture.ApplicationId
        $script:fixture.Writes.Count | Should Be 4
        $app = $script:fixture.Writes[0].Body
        $app.displayName | Should Be "SecureM365 Teams Assessment"
        $app.signInAudience | Should Be "AzureADMyOrg"
        $app.keyCredentials.Count | Should Be 1
        $app.keyCredentials[0].key |
            Should Be ([Convert]::ToBase64String($script:fixture.StoredCertificate.RawData))
        $app.requiredResourceAccess.Count | Should Be 1
        $app.requiredResourceAccess[0].resourceAppId | Should Be "00000003-0000-0000-c000-000000000000"
        $app.requiredResourceAccess[0].resourceAccess.Count | Should Be 1
        $app.requiredResourceAccess[0].resourceAccess[0].id | Should Be $script:fixture.OrganizationRoleId
        $app.requiredResourceAccess[0].resourceAccess[0].type | Should Be "Role"
        $script:fixture.Writes[2].Body.principalId | Should Be $script:fixture.PrincipalId
        $script:fixture.Writes[2].Body.resourceId | Should Be $script:fixture.GraphPrincipalId
        $script:fixture.Writes[3].Body.principalId | Should Be $script:fixture.PrincipalId
        $script:fixture.Writes[3].Body.roleDefinitionId | Should Be $script:fixture.TeamsRoleId
        $script:fixture.Writes[3].Body.directoryScopeId | Should Be "/"
        foreach ($scope in @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory")) {
            ($script:fixture.WriteScopes -contains $scope) | Should Be $true
            ($script:parameters.GraphParameters.AdditionalScopes -contains $scope) | Should Be $false
        }
        Assert-MockCalled New-SelfSignedCertificate -Times 1 -Exactly -Scope It -ParameterFilter {
            $Subject -eq $script:fixture.Subject -and $CertStoreLocation -eq "Cert:\CurrentUser\My" -and
            $KeyAlgorithm -eq "RSA" -and $KeyLength -eq 3072 -and $HashAlgorithm -eq "SHA256" -and
            $KeyExportPolicy -eq "NonExportable" -and $KeySpec -eq "Signature" -and
            $NotAfter -gt (Get-Date).AddMonths(11) -and $NotAfter -lt (Get-Date).AddMonths(13)
        }
        Assert-MockCalled Connect-MicrosoftTeams -Times 1 -Exactly -Scope It -ParameterFilter {
            $TenantId -eq $script:fixture.TenantId.Guid -and
            $ApplicationId -eq $script:fixture.ApplicationId -and
            $CertificateThumbprint -eq $script:fixture.StoredCertificate.Thumbprint -and
            -not $UseDeviceAuthentication
        }
        Assert-MockCalled Get-CsTeamsMeetingPolicy -Times 1 -Exactly -Scope It -ParameterFilter {
            $Identity -eq "Global"
        }
    }

    It "reuses the complete existing setup without new credentials, grants, or write-scope requests" {
        $null = Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false
        $script:fixture.WriteScopes = @()

        $result = Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false

        $result.Account | Should Be $script:fixture.ApplicationId
        $script:fixture.Writes.Count | Should Be 4
        $script:fixture.WriteScopes.Count | Should Be 0
        Assert-MockCalled New-SelfSignedCertificate -Times 1 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Graph -Times 1 -Exactly -Scope It
    }

    It "makes no setup writes or requests for write scopes when approval is not given" {
        { Connect-SecureM365AssessmentTeams @script:parameters -WhatIf } |
            Should Throw "setup was not approved"

        $script:fixture.Writes.Count | Should Be 0
        Assert-MockCalled New-SelfSignedCertificate -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Graph -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Exactly -Scope It
    }

    It "supports a separate application name and certificate subject" {
        $script:parameters.ApplicationDisplayName = "Separate AA assessment"
        $script:parameters.CertificateSubject = "CN=Separate AA assessment"

        $null = Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false

        $script:fixture.Application.displayName | Should Be "Separate AA assessment"
        $script:fixture.StoredCertificate.Subject | Should Be "CN=Separate AA assessment"
    }

    It "retries policy-access propagation without reprovisioning or falling back to user sign-in" {
        $script:fixture.PolicyFailures = 2

        $result = Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false

        $result.Account | Should Be $script:fixture.ApplicationId
        $script:fixture.Writes.Count | Should Be 4
        Assert-MockCalled New-SelfSignedCertificate -Times 1 -Exactly -Scope It
        Assert-MockCalled Connect-MicrosoftTeams -Times 3 -Exactly -Scope It -ParameterFilter {
            $ApplicationId -eq $script:fixture.ApplicationId -and -not $UseDeviceAuthentication
        }
        Assert-MockCalled Start-Sleep -Times 2 -Exactly -Scope It
    }

    It "reports retained setup and the original error after connection retries are exhausted" {
        $script:fixture.PolicyFailures = 10

        { Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false } |
            Should Throw "No changes were rolled back"

        $script:fixture.PolicyReads | Should Be 6
        $script:fixture.Writes.Count | Should Be 4
        Assert-MockCalled Start-Sleep -Times 5 -Exactly -Scope It
        Assert-MockCalled Remove-Item -Times 0 -Exactly -Scope It
    }

    It "stops on failed consent and reports partial objects without assigning additional roles" {
        $script:fixture.FailWrite = "appRoleAssignments"

        { Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false } |
            Should Throw "Confirmed changes"

        $script:fixture.Writes.Count | Should Be 3
        $script:fixture.DirectoryGrants.Count | Should Be 0
        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-Item -Times 0 -Exactly -Scope It
    }

    It "rejects ambiguous role discovery before requesting permissions or provisioning" {
        $script:fixture.DuplicateRole = $true

        { Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false } |
            Should Throw "uniquely resolve"

        $script:fixture.Writes.Count | Should Be 0
        Assert-MockCalled Connect-SecureM365Graph -Times 0 -Exactly -Scope It
    }

    It "does not create a certificate or application when setup Graph consent fails" {
        Mock Connect-SecureM365Graph { throw "Fixture setup consent denied." }

        { Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false } |
            Should Throw "Fixture setup consent denied"

        $script:fixture.Writes.Count | Should Be 0
        Assert-MockCalled New-SelfSignedCertificate -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-MicrosoftTeams -Times 0 -Exactly -Scope It
    }

    It "rejects an unsafe existing identity: <Case>" -TestCases @(
        @{ Case = "missing local key"; ExpectedError = "Only part" }
        @{ Case = "duplicate application"; ExpectedError = "ambiguous" }
        @{ Case = "duplicate certificate"; ExpectedError = "ambiguous" }
        @{ Case = "extra API permission"; ExpectedError = "requested permissions differ" }
        @{ Case = "different public certificate"; ExpectedError = "does not uniquely match" }
        @{ Case = "missing API grant"; ExpectedError = "application grants do not match" }
        @{ Case = "extra directory role"; ExpectedError = "directory roles do not match" }
        @{ Case = "disabled service principal"; ExpectedError = "enabled, matching service principal" }
        @{ Case = "client secret"; ExpectedError = "certificate-only application" }
    ) {
        param($Case, $ExpectedError)
        $null = Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false
        switch ($Case) {
            "missing local key" { $script:fixture.Certificates = @() }
            "duplicate application" { $script:fixture.Applications += $script:fixture.Application }
            "duplicate certificate" { $script:fixture.Certificates += $script:fixture.StoredCertificate }
            "extra API permission" {
                $script:fixture.Application.requiredResourceAccess[0].resourceAccess += @{
                    id = "33333333-3333-4333-8333-333333333333"; type = "Role"
                }
            }
            "different public certificate" { $script:fixture.Application.keyCredentials[0].key = "different" }
            "missing API grant" { $script:fixture.AppGrants = @() }
            "extra directory role" { $script:fixture.DirectoryGrants += $script:fixture.DirectoryGrants[0] }
            "disabled service principal" { $script:fixture.Principals[0].accountEnabled = $false }
            "client secret" { $script:fixture.Application.passwordCredentials = @(@{ keyId = "fixture-secret" }) }
        }

        { Connect-SecureM365AssessmentTeams @script:parameters -Confirm:$false } | Should Throw $ExpectedError

        $script:fixture.Writes.Count | Should Be 4
        Assert-MockCalled New-SelfSignedCertificate -Times 1 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Graph -Times 1 -Exactly -Scope It
        Assert-MockCalled Connect-MicrosoftTeams -Times 1 -Exactly -Scope It
    }
}

Describe "AA certificate validation" {
    It "rejects an expired certificate" {
        $certificate = New-MemoryTestCertificate -Subject "CN=AA fixture" `
            -NotAfter ([datetimeoffset]::UtcNow.AddDays(-1))
        try {
            { Assert-SecureM365TeamsCertificate $certificate } | Should Throw "currently valid"
        }
        finally {
            $certificate.Dispose()
        }
    }

    It "rejects an RSA key that is not 3072 bits" {
        $certificate = New-MemoryTestCertificate -Subject "CN=AA fixture" -KeySize 2048
        try {
            { Assert-SecureM365TeamsCertificate $certificate } | Should Throw "3072-bit"
        }
        finally {
            $certificate.Dispose()
        }
    }

    It "rejects exportable or unverifiably non-exportable private keys" {
        $certificate = New-MemoryTestCertificate -Subject "CN=AA fixture"
        try {
            { Assert-SecureM365TeamsCertificate $certificate } | Should Throw "non-exportable"
        }
        finally {
            $certificate.Dispose()
        }
    }
}

$wiringStatements = @($ast.EndBlock.Statements | Where-Object {
    ($_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -in @(
            '$explicitTeamsCertificate', '$useAutomaticTeamsCertificate',
            '$additionalScopes', '$graphParameters', '$readers'
        )) -or
    ($_ -is [System.Management.Automation.Language.IfStatementAst] -and
        $_.Clauses[0].Item1.Extent.Text -eq '$useAutomaticTeamsCertificate')
})
$wiringScript = [scriptblock]::Create(
    ($ast.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
    $ast.ParamBlock.Extent.Text + "`n" + ($wiringStatements.Extent.Text -join "`n") +
    "`n& `$readers.Teams"
)
$fullScript = [scriptblock]::Create(
    ($ast.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
    $ast.ParamBlock.Extent.Text + "`n" + ($ast.EndBlock.Statements.Extent.Text -join "`n")
)

Describe "AA Teams authentication routing" {
    BeforeEach {
        $script:assessmentTenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $script:discoveryScopes = @()
        Mock Connect-SecureM365AssessmentTeams {
            $script:discoveryScopes = @($GraphParameters.AdditionalScopes)
            [pscustomobject]@{ TenantId = $TenantId.Guid }
        }
        Mock Connect-SecureM365Teams { [pscustomobject]@{ TenantId = $TenantId.Guid } }
        Mock Get-SecureM365TeamsMeetingPolicy { [pscustomobject]@{ Identity = "Global" } }
        Mock Out-Host {}
        Mock Write-Host {}
        Mock Get-Module { [pscustomobject]@{ Name = $Name } }
        Mock Install-Module { throw "Module installation must not run under WhatIf." }
    }

    It "defaults to independent automatic certificate setup with read-only discovery scopes" {
        $result = & $wiringScript -ConsentForAllScripts:$false

        $result.Identity | Should Be "Global"
        ($script:discoveryScopes -join ",") | Should Be "Application.Read.All,Organization.Read.All"
        Assert-MockCalled Connect-SecureM365AssessmentTeams -Times 1 -Exactly -Scope It -ParameterFilter {
            $ApplicationDisplayName -eq "SecureM365 Teams Assessment"
        }
        Assert-MockCalled Connect-SecureM365Teams -Times 0 -Exactly -Scope It
    }

    It "preserves explicitly supplied certificate authentication without provisioning" {
        $null = & $wiringScript -ConsentForAllScripts:$false `
            -TeamsApplicationId "55555555-5555-4555-8555-555555555555" `
            -TeamsCertificateThumbprint "0123456789012345678901234567890123456789"

        Assert-MockCalled Connect-SecureM365AssessmentTeams -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Teams -Times 1 -Exactly -Scope It -ParameterFilter {
            $ApplicationId -eq [guid] "55555555-5555-4555-8555-555555555555" -and
            $CertificateThumbprint -eq "0123456789012345678901234567890123456789" -and
            $ValidateMeetingPolicyAccess
        }
    }

    It "preserves user authentication when explicitly selected" -TestCases @(
        @{ DeviceCode = $false }
        @{ DeviceCode = $true }
    ) {
        param($DeviceCode)
        $null = & $wiringScript -ConsentForAllScripts:$false `
            -UseTeamsUserAuthentication:(-not $DeviceCode) -UseTeamsDeviceAuthentication:$DeviceCode

        Assert-MockCalled Connect-SecureM365AssessmentTeams -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Teams -Times 1 -Exactly -Scope It -ParameterFilter {
            $UseDeviceAuthentication -eq $DeviceCode -and $ValidateMeetingPolicyAccess
        }
    }

    It "passes an explicit PFX and SecureString through without automatic setup" {
        $password = [securestring]::new()
        try {
            $null = & $wiringScript -ConsentForAllScripts:$false `
                -TeamsApplicationId "55555555-5555-4555-8555-555555555555" `
                -TeamsCertificatePath "C:\SecureM365Keys\fixture.pfx" -TeamsCertificatePassword $password

            Assert-MockCalled Connect-SecureM365AssessmentTeams -Times 0 -Exactly -Scope It
            Assert-MockCalled Connect-SecureM365Teams -Times 1 -Exactly -Scope It -ParameterFilter {
                $CertificatePath -eq "C:\SecureM365Keys\fixture.pfx" -and
                [object]::ReferenceEquals($CertificatePassword, $password) -and $ValidateMeetingPolicyAccess
            }
        }
        finally {
            $password.Dispose()
        }
    }

    It "rejects conflicting user and certificate options without provisioning" {
        {
            & $wiringScript -UseTeamsUserAuthentication `
                -TeamsApplicationId "55555555-5555-4555-8555-555555555555"
        } | Should Throw "cannot be combined"

        Assert-MockCalled Connect-SecureM365AssessmentTeams -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Teams -Times 0 -Exactly -Scope It
    }

    It "keeps the full script WhatIf path free of authentication and setup" {
        $output = @(& $fullScript -WhatIf)

        $output.Count | Should Be 0
        Assert-MockCalled Install-Module -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365AssessmentTeams -Times 0 -Exactly -Scope It
        Assert-MockCalled Connect-SecureM365Teams -Times 0 -Exactly -Scope It
    }
}
