#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$parseErrors = $null
$source = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $scriptsRoot "05-Verify-Admin-Permissions.ps1"), [ref] $null, [ref] $parseErrors
)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }

# Execute the production body with isolated service mocks, never its module imports.
$statements = @($source.EndBlock.Statements | Where-Object {
    $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
    $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
    $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
})
$script:checker = [scriptblock]::Create(
    ($source.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
    $source.ParamBlock.Extent.Text + "`n" + ($statements.Extent.Text -join "`n")
)
$templatesStatement = $source.EndBlock.Statements | Where-Object { $_.Left.Extent.Text -eq '$roleTemplates' }
$script:templates = & ([scriptblock]::Create($templatesStatement.Right.Extent.Text))
$scopesStatement = $source.EndBlock.Statements | Where-Object { $_.Left.Extent.Text -eq '$requiredScopes' }
$script:allScopes = @(& ([scriptblock]::Create($scopesStatement.Right.Extent.Text)))

$common = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $scriptsRoot "SecureM365.Common.psm1"), [ref] $null, [ref] $parseErrors
)
foreach ($statement in $common.EndBlock.Statements) {
    if (
        $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $statement.Name -in @(
            "Connect-SecureM365Graph", "Connect-SecureM365Teams", "Get-SecureM365GraphCollection",
            "Test-SecureM365TeamsServicePlanName", "Test-SecureM365CoreTeamsServicePlanName",
            "Get-SecureM365TeamsProvisioningStatus"
        )
    ) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}

function Connect-MgGraph {
    [CmdletBinding()]
    param(
        [string] $TenantId, [string[]] $Scopes, [string] $ContextScope,
        [switch] $NoWelcome, [switch] $UseDeviceCode, [securestring] $AccessToken
    )
    throw "Unmocked Graph connection."
}
function Invoke-SecureM365BrowserPkce {
    param([guid] $TenantId, [string[]] $Scopes)
    [pscustomobject]@{
        AccessToken = "opaque-fixture-token"
        Scopes = @($Scopes)
        TenantId = $TenantId.Guid
    }
}
function Get-MgContext { throw "Unmocked Graph context." }
function Get-Module {
    [CmdletBinding()]
    param([string] $Name, [switch] $ListAvailable)
    throw "Unmocked module discovery."
}
function Disconnect-MgGraph { [CmdletBinding()] param() throw "Unmocked Graph disconnect." }
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
function Get-CsTeamsMeetingPolicy { [CmdletBinding()] param() throw "Unmocked Teams policy read." }
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [uri] $Uri, [hashtable] $Headers, [string] $Body, [string] $ContentType)
    throw "Unmocked Graph request."
}

function Add-FixtureRole {
    param([string] $Name, [string] $PrincipalId = $script:fixture.UserId, [string] $Scope = "/")
    $assignment = @{
        id = "assignment-$($script:fixture.Assignments.Count + 1)"
        principalId = $PrincipalId
        roleDefinitionId = $script:templates[$Name]
        directoryScopeId = $Scope
    }
    [void] $script:fixture.Assignments.Add($assignment)
}

function Invoke-Checker {
    param(
        [switch] $CheckOnly,
        [switch] $WhatIf,
        [switch] $UseGraphBrowserPkce,
        [switch] $AttemptTeamsConnection,
        [switch] $UseTeamsDeviceAuthentication,
        [guid] $TeamsApplicationId = [guid]::Empty,
        [string] $TeamsCertificateThumbprint
    )
    & $script:checker -TenantId ([guid] $script:fixture.TenantId) -CheckOnly:$CheckOnly `
        -WhatIf:$WhatIf -UseGraphBrowserPkce:$UseGraphBrowserPkce `
        -AttemptTeamsConnection:$AttemptTeamsConnection `
        -UseTeamsDeviceAuthentication:$UseTeamsDeviceAuthentication `
        -TeamsApplicationId $TeamsApplicationId `
        -TeamsCertificateThumbprint $TeamsCertificateThumbprint `
        -Confirm:$false 6> $null
}

Describe "05 administrator permission verification (offline)" {
    BeforeEach {
        Remove-Variable SecureM365GraphContextMetadata -Scope Global -ErrorAction SilentlyContinue
        $script:fixture = @{
            TenantId = "11111111-1111-4111-8111-111111111111"
            UserId = "22222222-2222-4222-8222-222222222222"
            OtherUserId = "33333333-3333-4333-8333-333333333333"
            GroupId = "44444444-4444-4444-8444-444444444444"
            Upn = "lab-admin@example.com"
            TeamsAccount = "lab-admin@example.com"
            ExistingScopes = @($script:allScopes)
            Definitions = @($script:templates.Keys | ForEach-Object {
                @{ id = $script:templates[$_]; templateId = $script:templates[$_]; displayName = $_; isBuiltIn = $true }
            })
            Assignments = [System.Collections.Generic.List[object]]::new()
            Memberships = @()
            Requests = [System.Collections.Generic.List[object]]::new()
            Connects = [System.Collections.Generic.List[object]]::new()
            Warnings = [System.Collections.Generic.List[string]]::new()
            PostCount = 0
            RoleReads = 0
            TeamsReads = 0
            TeamsConnects = 0
            TeamsApplicationId = $null
            TeamsCertificateThumbprint = $null
            GraphDisconnects = 0
            TeamsDisconnects = 0
            FailPostNumber = 0
            FailPath = $null
            FailConsent = $false
            ChangeAccount = $false
            WrongTenant = $false
            AuthType = "Delegated"
            Environment = "Global"
            AccountEnabled = $true
            TeamsDenied = $false
            SecurityDefaultsEnabled = $true
            TenantTeamsPresent = $true
            TenantTeamsProvisioningStatus = "Success"
            UserTeamsLicensed = $true
            UserTeamsProvisioningStatus = "Success"
            UserTeamsCapabilityStatus = "Enabled"
            MissingModule = $null
            WrongPostPrincipal = $false
            WrongReadBack = $false
            NullPost = $false
            LoseAuthority = $false
            ConcurrentRole = $null
            Paged = $false
            FailSecondRolePage = $false
        }
        Mock Connect-MgGraph {
            param($TenantId, $Scopes, $ContextScope, $NoWelcome, $UseDeviceCode, $AccessToken)
            [void] $script:fixture.Connects.Add(@{ Scopes = @($Scopes); DeviceCode = [bool] $UseDeviceCode })
            if ($script:fixture.FailConsent -and $script:fixture.Connects.Count -gt 1) {
                throw "Admin consent denied."
            }
            $script:fixture.Context = [pscustomobject]@{
                TenantId = if ($AccessToken) { "" } elseif ($script:fixture.WrongTenant) { $script:fixture.OtherUserId } else { $TenantId }
                Scopes = if ($AccessToken) { @() } else { @(@($Scopes) + $script:fixture.ExistingScopes | Sort-Object -Unique) }
                Account = $script:fixture.Upn
                AuthType = if ($AccessToken) { "UserProvidedAccessToken" } else { $script:fixture.AuthType }
                Environment = $script:fixture.Environment
                ContextScope = $ContextScope
            }
        }
        Mock Get-MgContext { $script:fixture.Context }
        Mock Disconnect-MgGraph { $script:fixture.GraphDisconnects++ }
        Mock Get-Module {
            param($Name, $ListAvailable)
            if ($Name -ne $script:fixture.MissingModule) { [pscustomobject]@{ Name = $Name } }
        } -ParameterFilter { $ListAvailable -and $Name -in @(
            "Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns",
            "Microsoft.Graph.Identity.Governance", "MicrosoftTeams",
            "ExchangeOnlineManagement"
        ) }
        Mock Write-Warning { param($Message) [void] $script:fixture.Warnings.Add($Message) }
        Mock Out-Host {}
        Mock Connect-MicrosoftTeams {
            param($TenantId, $UseDeviceAuthentication, $ApplicationId, $CertificateThumbprint, $Certificate)
            $script:fixture.TeamsConnects++
            $script:fixture.TeamsApplicationId = [string] $ApplicationId
            $script:fixture.TeamsCertificateThumbprint = [string] $CertificateThumbprint
            [pscustomobject]@{ TenantId = $TenantId; Account = $script:fixture.TeamsAccount }
        }
        Mock Disconnect-MicrosoftTeams { $script:fixture.TeamsDisconnects++ }
        Mock Get-CsTeamsMeetingPolicy {
            $script:fixture.TeamsReads++
            if ($script:fixture.TeamsDenied) { throw "Forbidden: Access Denied." }
            [pscustomobject]@{ Identity = "Global" }
            [pscustomobject]@{ Identity = "Tag:Custom" }
        }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Headers, $Body, $ContentType)
            $address = [uri] $Uri
            $path = $address.AbsolutePath
            [void] $script:fixture.Requests.Add(@{ Method = $Method; Uri = $address; Body = $Body })
            if ($path -eq $script:fixture.FailPath) {
                $record = [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new("Forbidden"),
                    "PermissionProbeFailure", [System.Management.Automation.ErrorCategory]::PermissionDenied, $Uri
                )
                $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"message":"Fixture service permission detail"}}')
                throw $record
            }
            if ($path -like "/v1.0/roleManagement/*" -and $address.Query -match '(\?|&)\$top=') {
                throw "Role-management endpoints must not receive `$top."
            }
            if (
                $path -eq "/v1.0/roleManagement/directory/roleAssignments" -and
                [uri]::UnescapeDataString($address.Query) -match '(?i)(?:\?|&)\$select=[^&]*\bappScopeId\b'
            ) {
                throw "Request_BadRequest: Could not find a property named 'appScopeId' on type 'Microsoft.DirectoryServices.RoleAssignment'."
            }
            if ($Method -eq "POST") {
                $path | Should Be "/v1.0/roleManagement/directory/roleAssignments" | Out-Null
                $ContentType | Should Be "application/json" | Out-Null
                $script:fixture.PostCount++
                if ($script:fixture.PostCount -eq $script:fixture.FailPostNumber) { throw "Forbidden: role assignment rejected." }
                $assignment = $Body | ConvertFrom-Json -AsHashtable
                $assignment.principalId | Should Be $script:fixture.UserId | Out-Null
                $assignment.directoryScopeId | Should Be "/" | Out-Null
                $assignment.roleDefinitionId | Should Not Be $script:templates["Global Administrator"] | Out-Null
                $assignment.id = "created-$($script:fixture.PostCount)"
                if ($script:fixture.WrongPostPrincipal) { $assignment.principalId = $script:fixture.OtherUserId }
                [void] $script:fixture.Assignments.Add($assignment)
                if ($script:fixture.NullPost) { return }
                return $assignment
            }
            $Method | Should Be "GET" | Out-Null
            if ($path -like "/v1.0/roleManagement/directory/roleAssignments/*") {
                $id = [uri]::UnescapeDataString($path.Substring($path.LastIndexOf("/") + 1))
                $assignment = @($script:fixture.Assignments | Where-Object id -eq $id)[0].Clone()
                if ($script:fixture.WrongReadBack) { $assignment.directoryScopeId = "/administrativeUnits/test" }
                return $assignment
            }
            switch ($path) {
                "/v1.0/me" {
                    $id = if ($script:fixture.ChangeAccount -and $script:fixture.Connects.Count -gt 1) {
                        $script:fixture.OtherUserId
                    } else { $script:fixture.UserId }
                    $assignedPlans = @(if ($script:fixture.UserTeamsLicensed) {
                        @{
                            servicePlanId = "11111111-1111-4111-8111-111111111110"
                            service = "TEAMS1"
                            capabilityStatus = $script:fixture.UserTeamsCapabilityStatus
                        }
                    })
                    return @{
                        id = $id
                        userPrincipalName = $script:fixture.Upn
                        accountEnabled = $script:fixture.AccountEnabled
                        assignedPlans = $assignedPlans
                    }
                }
                "/v1.0/me/memberOf" { $items = @($script:fixture.Memberships) }
                "/v1.0/roleManagement/directory/roleDefinitions" { $items = @($script:fixture.Definitions) }
                "/v1.0/roleManagement/directory/roleAssignments" {
                    $script:fixture.RoleReads++
                    if ($script:fixture.RoleReads -gt 1 -and $script:fixture.LoseAuthority) {
                        $script:fixture.Assignments.Clear()
                    }
                    if ($script:fixture.RoleReads -eq 2 -and $script:fixture.ConcurrentRole) {
                        Add-FixtureRole $script:fixture.ConcurrentRole
                    }
                    if ($script:fixture.FailSecondRolePage -and $address.Query -eq "?page=2") {
                        throw "Second role page failed."
                    }
                    $items = @($script:fixture.Assignments)
                }
                "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" {
                    return @{ isEnabled = $script:fixture.SecurityDefaultsEnabled }
                }
                "/v1.0/subscribedSkus" {
                    $servicePlans = @(if ($script:fixture.TenantTeamsPresent) {
                        @{
                            servicePlanId = "11111111-1111-4111-8111-111111111110"
                            servicePlanName = "TEAMS1"
                            provisioningStatus = $script:fixture.TenantTeamsProvisioningStatus
                        }
                    } else {
                        @{
                            servicePlanId = "44444444-4444-4444-8444-444444444444"
                            servicePlanName = "EXCHANGE_S_STANDARD"
                            provisioningStatus = "Success"
                        }
                    })
                    return @{ value = @(@{
                        skuId = "55555555-5555-4555-8555-555555555555"
                        skuPartNumber = "Microsoft_Teams_Enterprise_New"
                        capabilityStatus = "Enabled"
                        servicePlans = $servicePlans
                    }) }
                }
                "/v1.0/me/licenseDetails" {
                    $servicePlans = @(if ($script:fixture.UserTeamsLicensed) {
                        @{
                            servicePlanId = "11111111-1111-4111-8111-111111111110"
                            servicePlanName = "TEAMS1"
                            provisioningStatus = $script:fixture.UserTeamsProvisioningStatus
                        }
                    })
                    return @{ value = @(@{
                        skuId = "55555555-5555-4555-8555-555555555555"
                        skuPartNumber = "Microsoft_Teams_Enterprise_New"
                        servicePlans = $servicePlans
                    }) }
                }
                "/v1.0/policies/authorizationPolicy" { return @{ id = "authorizationPolicy" } }
                "/v1.0/policies/defaultAppManagementPolicy" { return @{ id = "defaultAppManagementPolicy" } }
                "/v1.0/identity/conditionalAccess/policies" { return @{ value = @() } }
                "/v1.0/users" { return @{ value = @(@{ id = $script:fixture.UserId }) } }
                "/v1.0/domains" { return @{ value = @(@{ id = "example.onmicrosoft.com" }) } }
                "/v1.0/reports/authenticationMethods/userRegistrationDetails" { return @{ value = @() } }
                "/v1.0/security/secureScores" { return @{ value = @() } }
                "/v1.0/security/secureScoreControlProfiles" { return @{ value = @() } }
                default {
                    if ($path -like "/v1.0/users/*") { return @{ id = $script:fixture.OtherUserId } }
                    throw "Unexpected mock URL: $Uri"
                }
            }
            if ($script:fixture.Paged -and $items.Count -gt 1) {
                if ($address.Query -eq "?page=2") { return @{ value = @($items | Select-Object -Skip 1) } }
                return @{ value = @($items[0]); '@odata.nextLink' = "https://graph.microsoft.com${path}?page=2" }
            }
            @{ value = $items }
        }
    }

    It "covers every scope requested by the other scripts and shared module" {
        $scopeValues = @(
            foreach ($file in Get-ChildItem -LiteralPath $scriptsRoot -File) {
                if ($file.Extension -notin @(".ps1", ".psm1") -or $file.Name -eq "05-Verify-Admin-Permissions.ps1") { continue }
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref] $null, [ref] $null)
                $ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $node.Value -match '^(AuditLog|Directory|Domain|Policy|RoleManagement|SecurityEvents|User)\.[A-Za-z.]+$'
                }, $true) | ForEach-Object Value
            }
        ) | Sort-Object -Unique
        @($scopeValues | Where-Object { $_ -notin $script:allScopes }).Count | Should Be 0
        $script:allScopes.Count | Should Be 12
    }

    It "returns an empty membership collection from the fixture" {
        $page = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me/memberOf?$select=id'
        if ($null -eq $page.value) {
            throw "Invalid mock page: $($page | ConvertTo-Json -Depth 5 -Compress)"
        }
        @($page.value).Count | Should Be 0
    }

    It "rejects appScopeId selections like the directory role service" {
        {
            Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,appScopeId'
        } | Should Throw "Could not find a property named 'appScopeId'"
    }

    It "reads every role-assignment page in script 99 without selecting appScopeId" {
        Add-FixtureRole "Privileged Role Administrator"
        Add-FixtureRole "User Administrator" -Scope "/administrativeUnits/test"
        $script:fixture.Paged = $true
        $reportSource = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $scriptsRoot "99-Test-M365RecommendationStatus.ps1"), [ref] $null, [ref] $null
        )
        $readersStatement = $reportSource.EndBlock.Statements | Where-Object { $_.Left.Extent.Text -eq '$readers' }
        $readers = & ([scriptblock]::Create($readersStatement.Right.Extent.Text))
        $assignments = @(& $readers.RoleAssignments)
        $assignments.Count | Should Be 2
        $assignments[0].directoryScopeId | Should Be "/"
        $assignments[1].directoryScopeId | Should Be "/administrativeUnits/test"
        $assignments[0].ContainsKey("appScopeId") | Should Be $false
        $script:fixture.RoleReads | Should Be 2
    }

    It "recognizes Global Administrator without adding other roles" {
        Add-FixtureRole "Global Administrator"
        $result = Invoke-Checker
        $result.Ready | Should Be $true
        $result.RoleCoverage.Count | Should Be 8
        $result.MissingRoles.Count | Should Be 0
        $result.AccessChecks.Count | Should Be 11
        $script:fixture.PostCount | Should Be 0
    }

    It "requires confirmation support with high impact by default" {
        $binding = $source.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq "CmdletBinding" }
        ($binding.NamedArguments | Where-Object ArgumentName -eq "SupportsShouldProcess").Argument.SafeGetValue() | Should Be $true
        ($binding.NamedArguments | Where-Object ArgumentName -eq "ConfirmImpact").Argument.SafeGetValue() | Should Be "High"
    }

    It "recognizes broader existing roles without redundant grants" {
        foreach ($name in @("Security Administrator", "User Administrator", "Privileged Role Administrator", "Teams Administrator", "Global Reader")) {
            Add-FixtureRole $name
        }
        $result = Invoke-Checker
        $result.Ready | Should Be $true
        $script:fixture.PostCount | Should Be 0
    }

    It "recognizes group-based roles and follows all inventory pages" {
        $script:fixture.Memberships = @(
            @{ id = $script:fixture.OtherUserId; '@odata.type' = "#microsoft.graph.directoryRole" },
            @{ id = $script:fixture.GroupId; '@odata.type' = "#microsoft.graph.group" }
        )
        Add-FixtureRole "User Administrator"
        Add-FixtureRole "Global Administrator" -PrincipalId $script:fixture.GroupId
        $script:fixture.Paged = $true
        $result = Invoke-Checker
        $result.Ready | Should Be $true
        @($result.ActiveRoles | Where-Object Source -like "Group *").Count | Should Be 1
        @($script:fixture.Requests | Where-Object { $_.Uri.Query -eq "?page=2" }).Count | Should Be 3
    }

    It "lists missing roles and stops when role-assignment authority is absent" {
        $result = Invoke-Checker
        $result.CanAssignRoles | Should Be $false
        $result.Ready | Should Be $false
        $result.MissingRoles.Count | Should Be 6
        ("Privileged Role Administrator" -in $result.MissingRoles) | Should Be $true
        $result.BlockedReason | Should Match "will not switch accounts"
        $result.AccessChecks.Count | Should Be 0
        $script:fixture.Connects.Count | Should Be 1
        $script:fixture.PostCount | Should Be 0
    }

    It "does not treat a scoped role as tenant-wide authority" {
        Add-FixtureRole "Privileged Role Administrator" -Scope "/administrativeUnits/test"
        $result = Invoke-Checker
        $result.CanAssignRoles | Should Be $false
        $script:fixture.PostCount | Should Be 0
    }

    It "does not treat an app-scoped assignment as tenant-wide authority" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.Assignments[0].appScopeId = "/app"
        (Invoke-Checker).CanAssignRoles | Should Be $false
        $script:fixture.PostCount | Should Be 0
    }

    It "creates only five missing dedicated roles and verifies persistence" {
        Add-FixtureRole "Privileged Role Administrator"
        $result = Invoke-Checker
        $result.AssignmentsCreated.Count | Should Be 5
        ("Authentication Policy Administrator" -in $result.AssignmentsCreated.Role) | Should Be $false
        $result.MissingRoles.Count | Should Be 0
        $result.RequiresReconnect | Should Be $true
        $result.Ready | Should Be $false
        @($script:fixture.Requests | Where-Object { $_.Method -eq "GET" -and $_.Uri.AbsolutePath -like "*/roleAssignments/created-*" }).Count | Should Be 5
        $rerun = Invoke-Checker
        $rerun.Ready | Should Be $true
        $rerun.AssignmentsCreated.Count | Should Be 0
        $script:fixture.PostCount | Should Be 5
    }

    It "uses the planned User Administrator grant for both Secure Score and SSPR" {
        foreach ($name in @(
            "Privileged Role Administrator", "Conditional Access Administrator",
            "Reports Reader", "Teams Communications Administrator", "Authentication Policy Administrator",
            "Global Reader"
        )) { Add-FixtureRole $name }
        $result = Invoke-Checker
        $result.AssignmentsCreated.Count | Should Be 1
        $result.AssignmentsCreated[0].Role | Should Be "User Administrator"
        $result.MissingRoles.Count | Should Be 0
    }

    It "makes no role writes or write-scope requests in CheckOnly mode" {
        Add-FixtureRole "Privileged Role Administrator"
        $result = Invoke-Checker -CheckOnly
        $result.MissingRoles.Count | Should Be 5
        $script:fixture.PostCount | Should Be 0
        $script:fixture.Connects.Count | Should Be 1
        @($script:fixture.Connects[0].Scopes | Where-Object { $_ -match "ReadWrite|Create" }).Count | Should Be 0
    }

    It "makes no role writes or write-scope requests with WhatIf" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.ExistingScopes = @()
        $result = Invoke-Checker -WhatIf
        $result.Ready | Should Be $false
        $result.CanAssignRoles | Should Be $true
        $result.MissingRoles.Count | Should Be 5
        @($result.GraphPermissions | Where-Object Status -eq "NOT IN TOKEN").Count | Should Be 5
        $result.AssignmentsCreated.Count | Should Be 0
        $script:fixture.PostCount | Should Be 0
        $script:fixture.Connects.Count | Should Be 1
        @($script:fixture.Connects[0].Scopes | Where-Object { $_ -match "ReadWrite|Create" }).Count | Should Be 0
    }

    It "requests all required Graph scopes when approved" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.ExistingScopes = @()
        $result = Invoke-Checker
        $script:fixture.Connects.Count | Should Be 2
        @($script:allScopes | Where-Object { $_ -notin $script:fixture.Connects[1].Scopes }).Count | Should Be 0
        @($result.GraphPermissions | Where-Object Status -ne "IN TOKEN").Count | Should Be 0
        $result.Ready | Should Be $true
    }

    It "does not mislabel absent token scopes as missing roles" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.ExistingScopes = @()
        $result = Invoke-Checker -CheckOnly
        $result.MissingRoles.Count | Should Be 0
        @($result.GraphPermissions | Where-Object Status -eq "NOT IN TOKEN").Count | Should Be 5
        $result.Ready | Should Be $false
    }

    It "stops before role writes when interactive consent fails" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.ExistingScopes = @()
        $script:fixture.FailConsent = $true
        { Invoke-Checker } | Should Throw "Admin consent denied"
        $script:fixture.PostCount | Should Be 0
    }

    It "refuses to continue as a different Graph account after consent" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.ExistingScopes = @()
        $script:fixture.ChangeAccount = $true
        { Invoke-Checker } | Should Throw "account changed"
        $script:fixture.PostCount | Should Be 0
        $script:fixture.GraphDisconnects | Should Be 1
    }

    It "rejects the wrong Graph tenant before inventory or writes" {
        $script:fixture.WrongTenant = $true
        { Invoke-Checker } | Should Throw "did not connect"
        $script:fixture.Requests.Count | Should Be 0
    }

    It "rejects application-only authentication before reading user data" {
        $script:fixture.AuthType = "AppOnly"
        { Invoke-Checker } | Should Throw "delegated authentication"
        $script:fixture.Requests.Count | Should Be 0
    }

    It "rejects unsupported Graph cloud environments" {
        $script:fixture.Environment = "USGov"
        { Invoke-Checker } | Should Throw "worldwide tenant"
        $script:fixture.Requests.Count | Should Be 0
    }

    It "does not assign roles to a disabled account" {
        $script:fixture.AccountEnabled = $false
        { Invoke-Checker } | Should Throw "enabled signed-in user"
        $script:fixture.PostCount | Should Be 0
    }

    It "does not count another user's Global Administrator assignment" {
        Add-FixtureRole "Global Administrator" -PrincipalId $script:fixture.OtherUserId
        $result = Invoke-Checker
        $result.CanAssignRoles | Should Be $false
        $result.MissingRoles.Count | Should Be 6
        $script:fixture.PostCount | Should Be 0
    }

    It "fails closed with service details when the role inventory is denied" {
        $script:fixture.FailPath = "/v1.0/roleManagement/directory/roleAssignments"
        { Invoke-Checker } | Should Throw "Fixture service permission detail"
        $script:fixture.PostCount | Should Be 0
    }

    It "rejects an empty role definition inventory" {
        $script:fixture.Definitions = @()
        { Invoke-Checker } | Should Throw "no role definitions"
        $script:fixture.PostCount | Should Be 0
    }

    It "rejects incomplete membership data instead of assigning duplicate roles" {
        $script:fixture.Memberships = @(@{ id = $script:fixture.GroupId })
        { Invoke-Checker } | Should Throw "incomplete membership inventory"
        $script:fixture.PostCount | Should Be 0
    }

    It "does not remediate from a partial role inventory" {
        Add-FixtureRole "Privileged Role Administrator"
        Add-FixtureRole "User Administrator"
        $script:fixture.Paged = $true
        $script:fixture.FailSecondRolePage = $true
        { Invoke-Checker } | Should Throw "Second role page failed"
        $script:fixture.PostCount | Should Be 0
    }

    It "requires manual review of custom roles before granting built-in roles" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.Definitions += @{ id = "custom"; displayName = "Custom operator"; isBuiltIn = $false }
        [void] $script:fixture.Assignments.Add(@{ id = "custom-assignment"; principalId = $script:fixture.UserId; roleDefinitionId = "custom"; directoryScopeId = "/" })
        $result = Invoke-Checker
        $result.BlockedReason | Should Match "Custom role"
        $script:fixture.PostCount | Should Be 0
    }

    It "does not report readiness when a service read fails despite complete roles" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.FailPath = "/v1.0/reports/authenticationMethods/userRegistrationDetails"
        $result = Invoke-Checker
        $result.Ready | Should Be $false
        @($result.AccessChecks | Where-Object Status -eq "FAILED").Count | Should Be 1
        ($result.AccessChecks | Where-Object Status -eq "FAILED").Details | Should Match "Fixture service permission detail"
        $script:fixture.PostCount | Should Be 0
    }

    It "reports Teams Forbidden without granting more roles" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.TeamsDenied = $true
        $result = Invoke-Checker
        $result.Ready | Should Be $false
        ($result.AccessChecks | Where-Object Service -eq "Teams meeting policies").Status | Should Be "FAILED"
        $script:fixture.PostCount | Should Be 0
    }

    It "preflights Teams but blocks interactive validation in Copilot mode with Security Defaults" {
        Add-FixtureRole "Global Administrator"
        $result = Invoke-Checker -UseGraphBrowserPkce

        $result.Ready | Should Be $false
        $preflight = $result.AccessChecks | Where-Object Service -eq "Teams licensing and provisioning"
        $preflight.Status | Should Be "PASSED"
        $preflight.Code | Should Be "TEAMS_LICENSED_AND_PROVISIONED"
        $preflight.TenantReadyPlanCount | Should Be 1
        $preflight.UserReadyPlanCount | Should Be 1
        $meeting = $result.AccessChecks | Where-Object Service -eq "Teams meeting policies"
        $meeting.Status | Should Be "BLOCKED"
        $meeting.Code | Should Be "TEAMS_INTERACTIVE_VALIDATION_BLOCKED"
        $meeting.Details | Should Match "normal WAM-capable PowerShell host"
        $meeting.Details | Should Match "Do not disable Security Defaults"
        $script:fixture.TeamsConnects | Should Be 0
        $script:fixture.TeamsReads | Should Be 0
    }

    It "does not attempt Teams authentication when the tenant has no Teams license" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.TenantTeamsPresent = $false
        $result = Invoke-Checker -UseGraphBrowserPkce

        $result.Ready | Should Be $false
        $preflight = $result.AccessChecks | Where-Object Service -eq "Teams licensing and provisioning"
        $preflight.Status | Should Be "FAILED"
        $preflight.Code | Should Be "TEAMS_TENANT_ABSENT"
        ($result.AccessChecks | Where-Object Service -eq "Teams meeting policies").Code |
            Should Be "TEAMS_CONNECTION_BLOCKED_BY_PREFLIGHT"
        $script:fixture.TeamsConnects | Should Be 0
    }

    It "reports tenant Teams plans that are present but unavailable" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.TenantTeamsProvisioningStatus = "PendingProvisioning"
        $result = Invoke-Checker -UseGraphBrowserPkce

        $preflight = $result.AccessChecks | Where-Object Service -eq "Teams licensing and provisioning"
        $preflight.Status | Should Be "FAILED"
        $preflight.Code | Should Be "TEAMS_TENANT_PLANS_UNAVAILABLE"
        $preflight.TenantTeamsPlanCount | Should Be 1
        $script:fixture.TeamsConnects | Should Be 0
    }

    It "does not attempt Teams authentication when the administrator is unlicensed" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.UserTeamsLicensed = $false
        $result = Invoke-Checker -UseGraphBrowserPkce

        $result.Ready | Should Be $false
        $preflight = $result.AccessChecks | Where-Object Service -eq "Teams licensing and provisioning"
        $preflight.Status | Should Be "FAILED"
        $preflight.Code | Should Be "TEAMS_USER_UNLICENSED_OR_UNPROVISIONED"
        $script:fixture.TeamsConnects | Should Be 0
    }

    It "allows an explicit Teams connection attempt after a passing preflight" {
        Add-FixtureRole "Global Administrator"
        $result = Invoke-Checker -UseGraphBrowserPkce -AttemptTeamsConnection

        $result.Ready | Should Be $true
        ($result.AccessChecks | Where-Object Service -eq "Teams meeting policies").Status |
            Should Be "PASSED"
        $script:fixture.TeamsConnects | Should Be 1
        $script:fixture.TeamsReads | Should Be 1
    }

    It "uses application authentication without a Teams prompt or user Teams license" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.UserTeamsLicensed = $false
        $appId = "55555555-5555-4555-8555-555555555555"
        $thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567"

        $result = Invoke-Checker `
            -UseGraphBrowserPkce `
            -TeamsApplicationId $appId `
            -TeamsCertificateThumbprint $thumbprint

        $result.Ready | Should Be $true
        $preflight = $result.AccessChecks | Where-Object Service -eq "Teams licensing and provisioning"
        $preflight.Code | Should Be "TEAMS_TENANT_LICENSED_AND_PROVISIONED"
        ($result.AccessChecks | Where-Object Service -eq "Teams meeting policies").Status |
            Should Be "PASSED"
        $script:fixture.TeamsConnects | Should Be 1
        $script:fixture.TeamsApplicationId | Should Be $appId
        $script:fixture.TeamsCertificateThumbprint | Should Be $thumbprint
    }

    It "never attempts Teams device authentication in Copilot mode when Security Defaults is enabled" {
        Add-FixtureRole "Global Administrator"
        $result = Invoke-Checker -UseGraphBrowserPkce -AttemptTeamsConnection -UseTeamsDeviceAuthentication

        $result.Ready | Should Be $false
        $meeting = $result.AccessChecks | Where-Object Service -eq "Teams meeting policies"
        $meeting.Status | Should Be "BLOCKED"
        $meeting.Code | Should Be "TEAMS_DEVICE_AUTH_BLOCKED_BY_SECURITY_DEFAULTS"
        $meeting.Details | Should Match "530035"
        $script:fixture.TeamsConnects | Should Be 0
    }

    It "rejects a different Teams account before reading its policies" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.TeamsAccount = "other-admin@example.com"
        $result = Invoke-Checker
        $result.Ready | Should Be $false
        $script:fixture.TeamsReads | Should Be 0
        $script:fixture.TeamsDisconnects | Should Be 1
    }

    It "reports missing modules without installing anything" {
        Add-FixtureRole "Global Administrator"
        $script:fixture.MissingModule = "MicrosoftTeams"
        $result = Invoke-Checker
        $result.Ready | Should Be $false
        ($result.Modules | Where-Object Module -eq "MicrosoftTeams").Installed | Should Be $false
        $script:fixture.TeamsReads | Should Be 0
    }

    It "stops after the first rejected write without retrying or escalating" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.FailPostNumber = 1
        { Invoke-Checker } | Should Throw "role assignment rejected"
        $script:fixture.PostCount | Should Be 1
        ($script:fixture.Warnings -join " ") | Should Match "No changes were rolled back"
    }

    It "reports confirmed partial assignments when a later write fails" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.FailPostNumber = 2
        { Invoke-Checker } | Should Throw "role assignment rejected"
        $script:fixture.PostCount | Should Be 2
        ($script:fixture.Warnings -join " ") | Should Match "created-1"
    }

    It "does not retry an unconfirmed write" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.NullPost = $true
        { Invoke-Checker } | Should Throw "not confirmed"
        $script:fixture.PostCount | Should Be 1
    }

    It "rejects a returned assignment for the wrong principal" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.WrongPostPrincipal = $true
        { Invoke-Checker } | Should Throw "did not match"
        $script:fixture.PostCount | Should Be 1
    }

    It "rejects a read-back assignment with the wrong scope" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.WrongReadBack = $true
        { Invoke-Checker } | Should Throw "did not match"
        $script:fixture.PostCount | Should Be 1
    }

    It "rechecks active role-assignment authority before every grant" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.LoseAuthority = $true
        { Invoke-Checker } | Should Throw "authority is no longer active"
        $script:fixture.PostCount | Should Be 0
    }

    It "skips a role granted concurrently before confirmation completes" {
        Add-FixtureRole "Privileged Role Administrator"
        $script:fixture.ConcurrentRole = "Conditional Access Administrator"
        $result = Invoke-Checker
        $result.AssignmentsCreated.Count | Should Be 4
        $result.MissingRoles.Count | Should Be 0
    }
}
