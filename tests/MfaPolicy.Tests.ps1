#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"

function Get-MfaTestScriptBlock {
    param([string] $Name)

    $parseErrors = $null
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $Name), [ref] $null, [ref] $parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }
    $statements = @($source.EndBlock.Statements | Where-Object {
        $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
        $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
        $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
    })
    [scriptblock]::Create(
        ($source.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
        $source.ParamBlock.Extent.Text + "`n" + ($statements.Extent.Text -join "`n")
    )
}

$script:createMfaPolicy = Get-MfaTestScriptBlock "10-New-AdminMfaPolicy.ps1"
$script:testAdminMfa = Get-MfaTestScriptBlock "11-Test-AdminMfa.ps1"
$roleNamesAssignment = $script:createMfaPolicy.Ast.EndBlock.Statements |
    Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -eq '$adminRoleNames' }
$script:adminRoleNames = & ([scriptblock]::Create(
    "$($roleNamesAssignment.Extent.Text)`n`$adminRoleNames"
))

foreach ($name in @("SecureM365.Common.psm1", "99-Test-M365RecommendationStatus.ps1")) {
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $name), [ref] $null, [ref] $null
    )
    foreach ($statement in $source.EndBlock.Statements) {
        if (
            $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $statement.Name -in @(
                "Test-SecureM365CaTargetsAllUsers", "Test-SecureM365CaHasOnlyApprovedExclusions",
                "Test-SecureM365CaTargetsAllResources", "Test-SecureM365CaRequiresMfa",
                "Test-SecureM365CaPolicyScope", "Get-SecureM365MfaPolicyAssessment",
                "New-Assessment", "Get-CheckData", "Get-CheckedSecurityDefaults",
                "Get-RegistrationCoverage", "Get-MfaAssessment", "Save-RecommendationSnapshot",
                "Test-ReportMfaGrant", "Test-ReportPolicyScope"
            )
        ) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }
}

function Connect-SecureM365Graph {
    [CmdletBinding()]
    param([guid] $TenantId, [string[]] $AdditionalScopes, [switch] $UseDeviceCode)
    throw "Unmocked authentication."
}
function Get-MgRoleManagementDirectoryRoleDefinition {
    [CmdletBinding()]
    param([switch] $All)
    throw "Unmocked role-definition read."
}
function New-SecureM365ConditionalAccessPolicy {
    [CmdletBinding()]
    param([hashtable] $BodyParameter)
    throw "Unmocked policy creation."
}
function Get-SecureM365GraphCollection {
    [CmdletBinding()]
    param([string] $Uri)
    throw "Unmocked Graph collection read."
}
function Get-SecureM365SecurityDefaultsEnabled { throw "Unmocked security defaults read." }
function Test-SecureM365ScoreAction {
    param([string] $Title, [string] $ControlName)
    throw "Secure Score must not determine MFA policy presence."
}

function Invoke-MfaPolicyCheck {
    param([string] $Script, [switch] $ApproveExclusions)
    if ($Script -eq "11") {
        $parameters = @{ TenantId = $script:tenantId }
        if ($ApproveExclusions) { $parameters.ApprovedExcludedUserId = $script:emergencyIds }
        & $script:testAdminMfa @parameters
    }
    else {
        if ($ApproveExclusions) {
            $script:approvedExclusions = @{ ApprovedExcludedUserIds = @($script:emergencyIds.Guid) }
        }
        Get-MfaAssessment -Administrators
    }
}

Describe "MFA policy detection using script 10's actual payload (offline)" {
    BeforeEach {
        $script:tenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $script:emergencyIds = [guid[]] @(
            "22222222-2222-4222-8222-222222222222"
            "33333333-3333-4333-8333-333333333333"
        )
        $script:roleDefinitions = @($script:adminRoleNames | ForEach-Object {
            @{
                id = [guid]::NewGuid().Guid
                templateId = [guid]::NewGuid().Guid
                displayName = $_
                isBuiltIn = $true
            }
        })
        $script:registration = @($script:emergencyIds | ForEach-Object {
            @{
                id = $_.Guid
                userDisplayName = "Fixture emergency account"
                userPrincipalName = "fixture@example.invalid"
                isAdmin = $true
                isMfaCapable = $false
                methodsRegistered = @()
            }
        })
        $script:readFailures = @{}
        $script:approvedExclusions = @{}
        $script:data = @{
            SecurityDefaults = @{ isEnabled = $false }
            RoleDefinitions = $script:roleDefinitions
            RoleAssignments = @($script:roleDefinitions | ForEach-Object {
                @{ roleDefinitionId = $_.id; principalId = $script:emergencyIds[0].Guid }
            })
            Users = @($script:emergencyIds | ForEach-Object {
                @{ id = $_.Guid; accountEnabled = $true; userType = "Member" }
            })
            Registration = $script:registration
        }
        Mock Connect-SecureM365Graph { [pscustomobject]@{ TenantId = $script:tenantId.Guid } }
        Mock Get-MgRoleManagementDirectoryRoleDefinition { $script:roleDefinitions }
        Mock New-SecureM365ConditionalAccessPolicy {
            param($BodyParameter)
            $script:policy = $BodyParameter + @{ id = "44444444-4444-4444-8444-444444444444" }
            $script:policies = @($script:policy)
            $script:data.ConditionalAccess = $script:policies
            [pscustomobject] $script:policy
        }
        Mock Get-SecureM365GraphCollection {
            param($Uri)
            if ($Uri -like "*/identity/conditionalAccess/policies*") {
                if ($script:readFailures.ContainsKey("ConditionalAccess")) {
                    throw $script:readFailures.ConditionalAccess
                }
                return $script:policies
            }
            if ($Uri -like "*/roleManagement/directory/roleDefinitions?*") {
                if ($script:readFailures.ContainsKey("RoleDefinitions")) {
                    throw $script:readFailures.RoleDefinitions
                }
                return $script:roleDefinitions
            }
            if ($Uri -like "*/reports/authenticationMethods/userRegistrationDetails?*") {
                if ($script:readFailures.ContainsKey("Registration")) {
                    throw $script:readFailures.Registration
                }
                return $script:registration
            }
            throw "Unexpected Graph URI: $Uri"
        }
        Mock Get-SecureM365SecurityDefaultsEnabled { $script:data.SecurityDefaults.isEnabled }
        Mock Test-SecureM365ScoreAction { throw "Secure Score must not be read." }

        & $script:createMfaPolicy -TenantId $script:tenantId `
            -EmergencyAccessAccountId $script:emergencyIds -Confirm:$false | Out-Null
    }

    It "finds the enabled policy despite emergency exclusions and no registration in script <Script>" -TestCases @(
        @{ Script = "11" }
        @{ Script = "99" }
    ) {
        param($Script)
        $results = @(Invoke-MfaPolicyCheck $Script)
        $results.Count | Should Be 1
        $result = $results[0]
        $configuration = if ($Script -eq "11") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.PolicyFound | Should Be $true
        $configuration.EnabledPolicyFound | Should Be $true
        $configuration.Resolved | Should Be $true
        $configuration.CoverageVerified | Should Be $false
        $configuration.Policies[0].Id | Should Be $script:policy.id
        $configuration.Policies[0].DisplayName | Should Be "CA001 - Require MFA for administrator roles"
        $configuration.Policies[0].State | Should Be "enabled"
        $configuration.Policies[0].ExcludedUserIds.Count | Should Be 2
        $configuration.Policies[0].ExclusionsApproved | Should Be $false
        $result.Evidence | Should Match "not every account or sign-in"
        $configuration.ExclusionEvidence | Should Match $script:emergencyIds[0].Guid
        Assert-MockCalled Test-SecureM365ScoreAction -Times 0 -Scope It
    }

    It "uses exclusion approval only for the coverage advisory in script <Script>" -TestCases @(
        @{ Script = "11" }
        @{ Script = "99" }
    ) {
        param($Script)
        $result = Invoke-MfaPolicyCheck $Script -ApproveExclusions
        $configuration = if ($Script -eq "11") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.CoverageVerified | Should Be $true
        $configuration.MissingAdministrativeRoles.Count | Should Be 0
        $configuration.Policies[0].ExclusionsApproved | Should Be $true
    }

    It "keeps registration-report failures advisory in script <Script>" -TestCases @(
        @{ Script = "11" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:readFailures.Registration = "Fixture registration permission denied."
        $result = Invoke-MfaPolicyCheck $Script
        $result.Status | Should Be "IMPLEMENTED"
        if ($Script -eq "11") {
            $result.AdministratorsNotMfaCapable | Should Be $null
            $result.RegistrationEvidence | Should Match "Fixture registration permission denied"
        }
        else {
            $result.Evidence | Should Match "Fixture registration permission denied"
        }
    }

    It "keeps missing role inventory advisory in script <Script>" -TestCases @(
        @{ Script = "11" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:readFailures.RoleDefinitions = "Fixture role inventory unavailable."
        $result = Invoke-MfaPolicyCheck $Script
        $configuration = if ($Script -eq "11") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.CoverageVerified | Should Be $null
        $configuration.CoverageEvidence | Should Match "Fixture role inventory unavailable"
    }

    It "does not pass a <State> policy in script <Script>" -TestCases @(
        @{ Script = "11"; State = "disabled" }
        @{ Script = "11"; State = "enabledForReportingButNotEnforced" }
        @{ Script = "99"; State = "disabled" }
        @{ Script = "99"; State = "enabledForReportingButNotEnforced" }
    ) {
        param($Script, $State)
        $script:policy.state = $State
        $result = Invoke-MfaPolicyCheck $Script
        $configuration = if ($Script -eq "11") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $true
        $configuration.EnabledPolicyFound | Should Be $false
        $result.Evidence | Should Match $State
    }

    It "does not pass a failed policy read in script <Script>" -TestCases @(
        @{ Script = "11" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:readFailures.ConditionalAccess = "Fixture policy query failed."
        { Invoke-MfaPolicyCheck $Script } | Should Throw "Fixture policy query failed"
    }

    It "does not claim an absent policy exists in script <Script>" -TestCases @(
        @{ Script = "11" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:policies = @()
        $script:data.ConditionalAccess = @()
        $result = Invoke-MfaPolicyCheck $Script
        $configuration = if ($Script -eq "11") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $false
        $configuration.EnabledPolicyFound | Should Be $false
    }

    It "does not treat an empty administrator registration report as verified readiness" {
        $script:registration = @()
        $result = Invoke-MfaPolicyCheck "11"
        $result.Resolved | Should Be $true
        $result.AdministratorsNotMfaCapable | Should Be $null
        $result.RegistrationEvidence | Should Match "No administrator registration rows"
    }

    It "does not rely on the policy display name or a Secure Score control" {
        $script:policy.grantControls.builtInControls = @("compliantDevice")
        $result = Invoke-MfaPolicyCheck "11"
        $result.PolicyFound | Should Be $false
        $result.Resolved | Should Be $false
        Assert-MockCalled Test-SecureM365ScoreAction -Times 0 -Scope It
    }

    It "keeps resource and risk restrictions visible without changing the presence result" {
        $script:policy.conditions.applications.includeApplications = @("specific-app")
        $script:policy.conditions.signInRiskLevels = @("high")
        $result = Invoke-MfaPolicyCheck "11" -ApproveExclusions
        $result.Resolved | Should Be $true
        $result.CoverageVerified | Should Be $false
        $result.CoverageEvidence | Should Match "resource/client/risk conditions"
    }

    It "recognizes stronger MFA authentication strengths" -TestCases @(
        @{ StrengthId = "00000000-0000-0000-0000-000000000002" }
        @{ StrengthId = "00000000-0000-0000-0000-000000000003" }
        @{ StrengthId = "00000000-0000-0000-0000-000000000004" }
    ) {
        param($StrengthId)
        $script:policy.grantControls = @{
            operator = "OR"
            builtInControls = @()
            authenticationStrength = @{ id = $StrengthId }
        }
        (Invoke-MfaPolicyCheck "11").Resolved | Should Be $true
    }

    It "rejects grants that do not actually require MFA" -TestCases @(
        @{ Controls = @("mfa", "compliantDevice"); Operator = "OR" }
        @{ Controls = @("mfa", "block"); Operator = "AND" }
        @{ Controls = @("mfa"); Operator = "unknownFutureValue" }
    ) {
        param($Controls, $Operator)
        $script:policy.grantControls.builtInControls = $Controls
        $script:policy.grantControls.operator = $Operator
        (Invoke-MfaPolicyCheck "11").Resolved | Should Be $false
        (Get-MfaAssessment -Administrators).Status | Should Be "NOT-CONFIGURED"
    }

    It "recognizes MFA required alongside another AND grant" {
        $script:policy.grantControls.builtInControls = @("mfa", "compliantDevice")
        $script:policy.grantControls.operator = "AND"
        (Invoke-MfaPolicyCheck "11").Resolved | Should Be $true
    }

    It "does not count a directory-role-only policy as an all-user policy" {
        $result = Get-MfaAssessment
        $result.Status | Should Be "NOT-CONFIGURED"
        $result.PolicyConfiguration.PolicyFound | Should Be $false
    }

    It "finds an all-user policy despite exclusions and no user registration" {
        $script:policy.conditions.users.includeUsers = @("All")
        $script:policy.conditions.users.includeRoles = @()
        $result = Get-MfaAssessment
        $result.Status | Should Be "IMPLEMENTED"
        $result.PolicyConfiguration.PolicyFound | Should Be $true
        $result.PolicyConfiguration.CoverageVerified | Should Be $false
        $result.Evidence | Should Match "not reported MFA-capable"
    }

    It "accepts Graph hashtable and PSCustomObject representations consistently" {
        $script:policies = @($script:policy | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
        $script:data.ConditionalAccess = $script:policies
        $result = Invoke-MfaPolicyCheck "11" -ApproveExclusions
        $result.Resolved | Should Be $true
        $result.CoverageVerified | Should Be $true
        (Get-MfaAssessment -Administrators).Status | Should Be "IMPLEMENTED"
    }

    It "does not report an unknown policy state as successfully enabled" {
        $script:policy.state = "unknownFutureValue"
        { Invoke-MfaPolicyCheck "11" } | Should Throw "unrecognized state"
        { Get-MfaAssessment -Administrators } | Should Throw "unrecognized state"
    }

    It "recognizes Security Defaults without falsely claiming a CA policy was found" {
        $script:policies = @()
        $script:data.ConditionalAccess = @()
        $script:data.SecurityDefaults.isEnabled = $true
        $result = Invoke-MfaPolicyCheck "11"
        $result.Resolved | Should Be $true
        $result.PolicyFound | Should Be $false
        $result.SecurityDefaultsEnabled | Should Be $true
        (Get-MfaAssessment -Administrators).Status | Should Be "IMPLEMENTED"
    }

    It "uses Security Defaults when the CA inventory is unavailable and leaves presence unknown" {
        $script:data.SecurityDefaults.isEnabled = $true
        $script:readFailures.ConditionalAccess = "Fixture CA inventory unavailable."
        $result = Get-MfaAssessment -Administrators
        $result.Status | Should Be "IMPLEMENTED"
        $result.PolicyConfiguration.PolicyFound | Should Be $null
        $result.Evidence | Should Match "Fixture CA inventory unavailable"
    }

    It "preserves strict scope checking for the other Conditional Access recommendations" {
        $script:approvedExclusions = @{ ApprovedExcludedUserIds = @($script:emergencyIds.Guid) }
        $script:policy.conditions.signInRiskLevels = @("medium", "high")
        Test-ReportPolicyScope $script:policy | Should Be $false
        Test-ReportPolicyScope $script:policy -Risk SignIn | Should Be $true
        $script:policy.conditions.Remove("signInRiskLevels")
        $script:policy.conditions.clientAppTypes = @("exchangeActiveSync", "other")
        Test-ReportPolicyScope $script:policy | Should Be $false
        Test-ReportPolicyScope $script:policy -Legacy | Should Be $true
        $script:approvedExclusions = @{}
        Test-ReportPolicyScope $script:policy -Legacy | Should Be $false
    }

    It "exports the helpers used by copied scripts and assesses through the real module" {
        $module = Import-Module (Join-Path $scriptsRoot "SecureM365.Common.psm1") `
            -Prefix MfaOffline -Force -PassThru
        try {
            $module.ExportedFunctions.ContainsKey("Get-MfaOfflineSecureM365MfaPolicyAssessment") | Should Be $true
            $module.ExportedFunctions.ContainsKey("Test-MfaOfflineSecureM365CaPolicyScope") | Should Be $true
            $result = Get-MfaOfflineSecureM365MfaPolicyAssessment `
                -Policies @($script:policy) -Administrators -SecurityDefaultsEnabled:$false
            $result.Resolved | Should Be $true
            $result.Policies[0].Id | Should Be $script:policy.id
        }
        finally {
            Remove-Module -ModuleInfo $module -Force
        }
    }

    It "persists policy identity, state and exclusions in the report snapshot" {
        $result = Get-MfaAssessment -Administrators
        $path = Save-RecommendationSnapshot -Results @($result) `
            -TenantId $script:tenantId -CheckedAt ([datetimeoffset]::UtcNow) -Directory $TestDrive
        $saved = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
        $saved[0].PolicyConfiguration.PolicyFound | Should Be $true
        $saved[0].PolicyConfiguration.Policies[0].Id | Should Be $script:policy.id
        $saved[0].PolicyConfiguration.Policies[0].State | Should Be "enabled"
        $saved[0].PolicyConfiguration.Policies[0].ExcludedUserIds.Count | Should Be 2
        $reportSource = Get-Content -LiteralPath (Join-Path $scriptsRoot "99-Test-M365RecommendationStatus.ps1") -Raw
        $reportSource | Should Match 'PolicyConfiguration\s*=\s*\$assessment\.PolicyConfiguration'
    }
}
