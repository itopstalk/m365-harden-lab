#Requires -Version 7.2

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
$script:teardownPath = Join-Path $scriptsRoot "07-Remove-TeamsCertificateApplication.ps1"
$script:setupScript = Get-TestScriptBlock $script:setupPath
$script:teardownScript = Get-TestScriptBlock $script:teardownPath

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
function Connect-SecureM365Teams {
    param(
        [guid] $TenantId,
        [guid] $ApplicationId,
        [string] $CertificateThumbprint,
        [switch] $ValidateMeetingPolicyAccess
    )
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
