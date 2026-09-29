#Requires -Version 7.2

$root = Split-Path $PSScriptRoot -Parent
$scriptsRoot = Join-Path $root "scripts"
$modulePath = Join-Path $scriptsRoot "SecureM365.Common.psm1"
Import-Module $modulePath -Force

function Get-TestableScript {
    param([Parameter(Mandatory)][string] $Path)

    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref] $null, [ref] $errors
    )
    if ($errors.Count -gt 0) { throw ($errors.Message -join "; ") }
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

$authScript = Get-TestableScript (Join-Path $scriptsRoot "62-Test-BaselineAuthenticationAndApps.ps1")
$exchangeScript = Get-TestableScript (Join-Path $scriptsRoot "64-Test-BaselineExchangeOnline.ps1")
$tenantId = [guid] "11111111-1111-4111-8111-111111111111"

function Connect-ExchangeOnline {
    [CmdletBinding()]
    param([string] $UserPrincipalName, [switch] $ShowBanner)
    throw "Unmocked Exchange Online connection."
}
function Get-ConnectionInformation {
    [CmdletBinding()]
    param()
    throw "Unmocked Exchange Online connection inventory."
}
function Get-OrganizationConfig {
    [CmdletBinding()]
    param()
    throw "Unmocked Exchange organization read."
}

Describe "Baseline Security Mode catalog" {
    It "contains every documented setting and secure expected value exactly once" {
        $expected = [ordered]@{
            "AUTH-001" = "Enabled Conditional Access policy for the documented privileged roles and Microsoft Admin Portals requiring the phishing-resistant MFA authentication strength"
            "AUTH-002" = "Enabled Conditional Access block policy for all users and resources covering Exchange ActiveSync and other legacy clients"
            "ENTRA-APP-001" = "passwordAddition restriction enabled for applications and service principals in the default app management policy"
            "ENTRA-APP-002" = "Only managePermissionGrantsForSelf.microsoft-user-default-low is assigned to the default user role"
            "APPS-001" = "Baseline Security Mode locks Basic authentication prompts off in Office Trust Center"
            "APPS-002" = "Office Cloud Policy Service Block Insecure Protocols policy enforced"
            "APPS-003" = "Office Cloud Policy Service Restrict Apps from FPRPC Fallback policy enforced"
            "SPO-001" = "Legacy RPS protocol unavailable; legacy browser authentication was deprecated for enterprise tenants in October 2025"
            "SPO-002" = "LegacyAuthProtocolsEnabled = false"
            "SPO-003" = "Baseline Security Mode permanently blocks new custom scripts across SharePoint and OneDrive"
            "SPO-004" = "DisableSharePointStoreAccess = true"
            "EXO-001" = "EwsEnabled = false at the organization level"
            "FILES-001" = "Documented Office Cloud Policy Service file-block policies enforced"
            "FILES-002" = "Documented Office Cloud Policy Service file-block policies enforced"
            "FILES-003" = "Office Cloud Policy Service Disable All ActiveX policy enforced"
            "FILES-004" = "Office Cloud Policy Service Block OrgChart and Block OLE Graph policies enforced"
            "FILES-005" = "Office Cloud Policy Service Don't allow Dynamic Data Exchange server launch in Excel policy enforced"
            "FILES-006" = "Office Cloud Policy Service Disable Publisher policy enforced"
            "ROOMS-001" = "RestrictResourceAccountAccess = true"
            "ROOMS-002" = "Documented dynamic resource-account group, Conditional Access compliance policy, and access-package join window are all configured"
        }
        $catalog = @(Get-SecureM365BaselineCatalog)
        $catalog.Count | Should Be 20
        @($catalog | Group-Object SettingId | Where-Object Count -ne 1).Count | Should Be 0
        foreach ($item in $catalog) {
            $expected.Contains($item.SettingId) | Should Be $true
            $item.ExpectedValue | Should Be $expected[$item.SettingId]
            $item.SourceUrl | Should Match '^https://learn\.microsoft\.com/'
            $item.Workload | Should Not BeNullOrEmpty
        }
    }

    It "classifies five settings as directly automated and fifteen as manual or unavailable" {
        $catalog = @(Get-SecureM365BaselineCatalog)
        @($catalog | Where-Object Automation -eq "Graph").Count | Should Be 4
        @($catalog | Where-Object Automation -eq "Exchange").Count | Should Be 1
        @($catalog | Where-Object Automation -eq "Manual").Count | Should Be 15
    }

    It "does not permit success-shaped UNKNOWN results" {
        $entry = Get-SecureM365BaselineCatalog | Select-Object -First 1
        {
            New-SecureM365BaselineResult -CatalogEntry $entry -Status UNKNOWN `
                -Resolved $true -ActualValue $null -Evidence "unavailable"
        } | Should Throw "must not contain"
    }
}

Describe "Authentication and app policy checks" {
    BeforeEach {
        $script:connectionFails = $false
        $script:malformedAppPolicy = $false
        $script:emptyPolicies = $false
        $script:adminRoles = @(
            "62e90394-69f5-4237-9190-012177145e10", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea10c",
            "c4e39bd9-1100-46d3-8c65-fb160da0071f", "b0f54661-2d74-4c50-afa3-1ec803f12efe",
            "158c047a-c907-4556-b7ef-446551a6b5f7", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
            "29232cdf-9323-42fd-ade2-1d097af3e4de", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
            "7495fdc4-34c4-4d15-a289-98788ce399fd", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
            "e8611ab8-c189-46e8-94e1-60213ab1f814", "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "fe930be7-5e62-47db-91af-98c3a49a38b1"
        )
        Mock Connect-SecureM365Graph {
            if ($script:connectionFails) { throw "fixture connection denied" }
        }
        Mock Get-SecureM365GraphCollection {
            if ($script:emptyPolicies) { return @() }
            @(
                @{
                    id = "phishing"
                    displayName = "Baseline phishing-resistant admins"
                    state = "enabled"
                    conditions = @{
                        users = @{ includeRoles = $script:adminRoles }
                        applications = @{ includeApplications = @("MicrosoftAdminPortals") }
                    }
                    grantControls = @{
                        authenticationStrength = @{ id = "00000000-0000-0000-0000-000000000004" }
                        builtInControls = @()
                    }
                },
                @{
                    id = "legacy"
                    displayName = "Baseline block legacy"
                    state = "enabled"
                    conditions = @{
                        users = @{ includeUsers = @("All") }
                        applications = @{ includeApplications = @("All") }
                        clientAppTypes = @("exchangeActiveSync", "other")
                    }
                    grantControls = @{ builtInControls = @("block") }
                }
            )
        }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            $Method | Should Be "GET"
            if ($Uri -like "*/defaultAppManagementPolicy") {
                if ($script:malformedAppPolicy) { return @{ id = "policy" } }
                return @{
                    id = "policy"
                    applicationRestrictions = @{
                        passwordCredentials = @(@{ restrictionType = "passwordAddition"; state = "enabled" })
                    }
                    servicePrincipalRestrictions = @{
                        passwordCredentials = @(@{ restrictionType = "passwordAddition"; state = "enabled" })
                    }
                }
            }
            if ($Uri -like "*/authorizationPolicy") {
                return @{
                    defaultUserRolePermissions = @{
                        permissionGrantPoliciesAssigned = @(
                            "managePermissionGrantsForSelf.microsoft-user-default-low"
                        )
                    }
                }
            }
            throw "Unexpected URI $Uri"
        }
    }

    It "returns four enabled results from complete secure responses" {
        $results = @(& $authScript -TenantId $tenantId)
        $results.Count | Should Be 4
        @($results | Where-Object Status -eq "ENABLED").Count | Should Be 4
        @($results | Where-Object Resolved -ne $true).Count | Should Be 0
    }

    It "routes browser PKCE and device-code parameters to the common authenticator" {
        & $authScript -TenantId $tenantId -UseGraphBrowserPkce | Out-Null
        Assert-MockCalled Connect-SecureM365Graph -Times 1 -ParameterFilter {
            $UseBrowserPkce -and -not $UseDeviceCode -and "Policy.Read.All" -in $AdditionalScopes
        }
    }

    It "reports every setting UNKNOWN when authentication is unavailable" {
        $script:connectionFails = $true
        $results = @(& $authScript -TenantId $tenantId)
        @($results | Where-Object Status -eq "UNKNOWN").Count | Should Be 4
        @($results | Where-Object { $null -ne $_.Resolved }).Count | Should Be 0
    }

    It "reports malformed app-policy data UNKNOWN rather than disabled" {
        $script:malformedAppPolicy = $true
        $result = & $authScript -TenantId $tenantId |
            Where-Object SettingId -eq "ENTRA-APP-001"
        $result.Status | Should Be "UNKNOWN"
        $result.Resolved | Should BeNullOrEmpty
        $result.Evidence | Should Match "malformed"
    }

    It "treats an authoritative empty Conditional Access collection as disabled" {
        $script:emptyPolicies = $true
        $results = @(& $authScript -TenantId $tenantId)
        @($results | Where-Object SettingId -like "AUTH-*" | Where-Object Status -eq "DISABLED").Count |
            Should Be 2
    }
}

Describe "Exchange Online baseline check" {
    BeforeEach {
        $script:connectionTenant = $tenantId.Guid
        $script:ewsEnabled = $false
        Mock Connect-ExchangeOnline {}
        Mock Get-ConnectionInformation {
            [pscustomobject]@{ TenantID = $script:connectionTenant; State = "Connected" }
        }
        Mock Get-OrganizationConfig {
            [pscustomobject]@{ EwsEnabled = $script:ewsEnabled }
        }
    }

    It "reports explicit organization-wide EWS disablement enabled" {
        $result = & $exchangeScript -TenantId $tenantId -ExchangeUserPrincipalName "admin@example.com"
        $result.Status | Should Be "ENABLED"
        $result.Resolved | Should Be $true
        Assert-MockCalled Connect-ExchangeOnline -Times 1 -ParameterFilter {
            $UserPrincipalName -eq "admin@example.com" -and $ShowBanner -eq $false
        }
    }

    It "treats a null EwsEnabled value as disabled baseline protection" {
        $script:ewsEnabled = $null
        $result = & $exchangeScript -TenantId $tenantId
        $result.Status | Should Be "DISABLED"
        $result.Resolved | Should Be $false
        $result.Evidence | Should Match "allowing EWS"
    }

    It "reports wrong-tenant or unavailable data UNKNOWN" {
        $script:connectionTenant = "22222222-2222-4222-8222-222222222222"
        $result = & $exchangeScript -TenantId $tenantId
        $result.Status | Should Be "UNKNOWN"
        $result.Resolved | Should BeNullOrEmpty
        Assert-MockCalled Get-OrganizationConfig -Times 0 -Scope It
    }
}

Describe "Manual and consolidated reporting" {
    It "returns all fifteen unavailable settings explicitly UNKNOWN" {
        $results = @(
            & (Join-Path $scriptsRoot "63-Test-BaselineSharePointAndOneDrive.ps1")
            & (Join-Path $scriptsRoot "65-Test-BaselineMicrosoft365Apps.ps1")
            & (Join-Path $scriptsRoot "66-Test-BaselineTeamsAndCollaboration.ps1")
        )
        $results.Count | Should Be 15
        @($results | Where-Object Status -eq "UNKNOWN").Count | Should Be 15
        @($results | Where-Object { $null -ne $_.Resolved }).Count | Should Be 0
        @($results | Where-Object { [string]::IsNullOrWhiteSpace($_.Evidence) }).Count | Should Be 0
    }

    It "calculates aggregate totals and rejects missing settings" {
        $catalog = @(Get-SecureM365BaselineCatalog)
        $results = @(
            for ($index = 0; $index -lt $catalog.Count; $index++) {
                $status = if ($index -lt 3) { "ENABLED" } elseif ($index -lt 5) { "DISABLED" } else { "UNKNOWN" }
                $resolved = if ($status -eq "UNKNOWN") { $null } else { $status -eq "ENABLED" }
                New-SecureM365BaselineResult -CatalogEntry $catalog[$index] -Status $status `
                    -Resolved $resolved -ActualValue $null -Evidence "fixture"
            }
        )
        $report = New-SecureM365BaselineReport -TenantId $tenantId -Results $results
        $report.Total | Should Be 20
        $report.Enabled | Should Be 3
        $report.Disabled | Should Be 2
        $report.Unknown | Should Be 15
        { New-SecureM365BaselineReport -TenantId $tenantId -Results @($results | Select-Object -Skip 1) } |
            Should Throw "incomplete"
    }
}

Describe "Read-only safeguards and prerequisites" {
    It "contains no tenant write cmdlets or mutating HTTP methods in baseline scripts" {
        $files = Get-ChildItem $scriptsRoot -Filter "*-Test-Baseline*.ps1"
        foreach ($file in $files) {
            $source = Get-Content $file.FullName -Raw
            $source | Should Not Match '(?im)-Method\s+(POST|PUT|PATCH|DELETE)\b'
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $file.FullName, [ref] $null, [ref] $errors
            )
            $commands = @(
                $ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true) | ForEach-Object GetCommandName | Where-Object { $_ }
            )
            @($commands | Where-Object { $_ -match '^(Set|Remove|Update|Add)-' }).Count | Should Be 0
            @($commands | Where-Object {
                $_ -match '^New-' -and $_ -notin @("New-SecureM365BaselineResult", "New-SecureM365BaselineReport", "New-UnknownResult")
            }).Count | Should Be 0
        }
    }

    It "installs Exchange Online and preflights the default app policy with no new Graph scope" {
        $installer = Get-Content (Join-Path $scriptsRoot "00-Install-PowerShellTools.ps1") -Raw
        $preflight = Get-Content (Join-Path $scriptsRoot "05-Verify-Admin-Permissions.ps1") -Raw
        $installer | Should Match '"ExchangeOnlineManagement"'
        $preflight | Should Match '"ExchangeOnlineManagement"'
        $preflight | Should Match 'policies/defaultAppManagementPolicy'
        $preflight | Should Match 'Capability = "Read the default app management policy"'
        $preflight | Should Match 'Role = "Global Reader"'
    }
}
