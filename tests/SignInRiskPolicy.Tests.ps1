#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"

function Get-SignInRiskTestScriptBlock {
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

$script:createSignInRiskPolicy = Get-SignInRiskTestScriptBlock "16-New-SignInRiskPolicy.ps1"
$script:testSignInRiskPolicy = Get-SignInRiskTestScriptBlock "17-Test-SignInRiskPolicy.ps1"
foreach ($name in @("SecureM365.Common.psm1", "99-Test-M365RecommendationStatus.ps1")) {
    $parseErrors = $null
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $name), [ref] $null, [ref] $parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }
    foreach ($statement in $source.EndBlock.Statements) {
        if (
            $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $statement.Name -in @(
                "Test-SecureM365CaTargetsAllUsers", "Test-SecureM365CaHasOnlyApprovedExclusions",
                "Test-SecureM365CaTargetsAllResources", "Test-SecureM365CaRequiresMfa",
                "Test-SecureM365CaPolicyScope", "Test-SecureM365CaUsesEveryTimeSignInFrequency",
                "Get-SecureM365MfaPolicyAssessment", "New-Assessment", "Get-CheckData",
                "Get-CheckedSecurityDefaults", "Test-ReportPolicyScope", "Test-ReportMfaGrant",
                "Get-RiskAssessment", "Save-RecommendationSnapshot"
            )
        ) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }
}
$checksAssignment = $source.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $_.Left.Extent.Text -eq '$checks'
}
$script:riskReportChecks = & ([scriptblock]::Create("$($checksAssignment.Extent.Text)`n`$checks"))
$script:signInRiskReportCheck = @($script:riskReportChecks | Where-Object {
    $_.Title -eq "Enable Microsoft Entra ID Identity Protection sign-in risk policies"
})
if ($script:signInRiskReportCheck.Count -ne 1) { throw "Expected exactly one sign-in risk recommendation." }
$script:signInRiskReportCheck = $script:signInRiskReportCheck[0]

function Connect-SecureM365Graph {
    [CmdletBinding()]
    param([guid] $TenantId, [string[]] $AdditionalScopes, [switch] $UseDeviceCode)
    throw "Unmocked authentication."
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
function Test-SecureM365ScoreAction {
    param([string] $Title, [string] $ControlName)
    throw "Secure Score must not determine sign-in risk policy presence."
}

function Invoke-SignInRiskPolicyCheck {
    param([string] $Script, [switch] $ApproveExclusions)
    if ($Script -eq "17") {
        $parameters = @{ TenantId = $script:tenantId }
        if ($ApproveExclusions) { $parameters.ApprovedExcludedUserId = $script:emergencyIds }
        & $script:testSignInRiskPolicy @parameters
    }
    else {
        if ($ApproveExclusions) {
            $script:approvedExclusions = @{ ApprovedExcludedUserIds = @($script:emergencyIds.Guid) }
        }
        & $script:signInRiskReportCheck.Evaluate
    }
}

Describe "Sign-in risk detection using script 16's actual payload (offline)" {
    BeforeEach {
        $script:tenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $script:emergencyIds = [guid[]] @(
            "22222222-2222-4222-8222-222222222222"
            "33333333-3333-4333-8333-333333333333"
        )
        $script:readFailures = @{}
        $script:approvedExclusions = @{}
        $script:data = @{ SecurityDefaults = @{ isEnabled = $false } }
        Mock Connect-SecureM365Graph { [pscustomobject]@{ TenantId = $script:tenantId.Guid } }
        Mock New-SecureM365ConditionalAccessPolicy {
            param($BodyParameter)
            $script:policy = $BodyParameter + @{ id = "44444444-4444-4444-8444-444444444444" }
            $script:data.ConditionalAccess = @($script:policy)
            [pscustomobject] $script:policy
        }
        Mock Get-SecureM365GraphCollection {
            param($Uri)
            if ($Uri -like "*/identity/conditionalAccess/policies*") {
                if ($script:readFailures.ContainsKey("ConditionalAccess")) {
                    throw $script:readFailures.ConditionalAccess
                }
                return $script:data.ConditionalAccess
            }
            throw "Unexpected Graph URI: $Uri"
        }
        Mock Test-SecureM365ScoreAction { throw "Secure Score must not be read." }
        & $script:createSignInRiskPolicy -TenantId $script:tenantId `
            -EmergencyAccessAccountId $script:emergencyIds -Confirm:$false | Out-Null
    }

    It "finds script 16's enabled policy despite emergency exclusions in script <Script>" -TestCases @(
        @{ Script = "17" }
        @{ Script = "99" }
    ) {
        param($Script)
        $results = @(Invoke-SignInRiskPolicyCheck $Script)
        $results.Count | Should Be 1
        $result = $results[0]
        $configuration = if ($Script -eq "17") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.PolicyFound | Should Be $true
        $configuration.EnabledPolicyFound | Should Be $true
        $configuration.ProtectionConfigured | Should Be $true
        $configuration.Resolved | Should Be $true
        $configuration.CoverageVerified | Should Be $false
        $configuration.Policies.Count | Should Be 1
        $configuration.Policies[0].Id | Should Be $script:policy.id
        $configuration.Policies[0].DisplayName | Should Be "CA004 - Require MFA for medium and high sign-in risk"
        $configuration.Policies[0].State | Should Be "enabled"
        $configuration.Policies[0].ExcludedUserIds.Count | Should Be 2
        $configuration.Policies[0].ExclusionsApproved | Should Be $false
        ($configuration.Policies[0].SignInRiskLevels -join ",") | Should Be "medium,high"
        $configuration.Policies[0].SignInFrequency.IsEnabled | Should Be $true
        $configuration.Policies[0].SignInFrequency.FrequencyInterval | Should Be "everyTime"
        $configuration.Policies[0].SignInFrequency.AuthenticationType | Should Be "primaryAndSecondaryAuthentication"
        $result.Evidence | Should Match "not every account or sign-in"
        $configuration.ExclusionEvidence | Should Match $script:emergencyIds[0].Guid
        if ($Script -eq "17") { $result.MatchingPolicies[0] | Should Be $script:policy.displayName }
        Assert-MockCalled Test-SecureM365ScoreAction -Times 0 -Scope It
    }

    It "uses approved exclusions only for coverage in script <Script>" -TestCases @(
        @{ Script = "17" }
        @{ Script = "99" }
    ) {
        param($Script)
        $result = Invoke-SignInRiskPolicyCheck $Script -ApproveExclusions
        $configuration = if ($Script -eq "17") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.CoverageVerified | Should Be $true
        $configuration.Policies[0].ExclusionsApproved | Should Be $true
    }

    It "keeps <Restriction> as a coverage advisory in script <Script>" -TestCases @(
        foreach ($number in @("17", "99")) {
            foreach ($restriction in @("BrowserOnly", "Application", "Location", "UserRisk")) {
                @{ Script = $number; Restriction = $restriction }
            }
        }
    ) {
        param($Script, $Restriction)
        switch ($Restriction) {
            "BrowserOnly" { $script:policy.conditions.clientAppTypes = @("browser") }
            "Application" { $script:policy.conditions.applications.excludeApplications = @("specific-app") }
            "Location" {
                $script:policy.conditions.locations = @{
                    includeLocations = @("All"); excludeLocations = @("AllTrusted")
                }
            }
            "UserRisk" { $script:policy.conditions.userRiskLevels = @("high") }
        }
        $result = Invoke-SignInRiskPolicyCheck $Script -ApproveExclusions
        $configuration = if ($Script -eq "17") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.CoverageVerified | Should Be $false
    }

    It "does not pass a <State> policy in script <Script>" -TestCases @(
        foreach ($number in @("17", "99")) {
            foreach ($state in @("disabled", "enabledForReportingButNotEnforced")) {
                @{ Script = $number; State = $state }
            }
        }
    ) {
        param($Script, $State)
        $script:policy.state = $State
        $result = Invoke-SignInRiskPolicyCheck $Script
        $configuration = if ($Script -eq "17") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $true
        $configuration.EnabledPolicyFound | Should Be $false
        if ($Script -eq "17") { $result.MatchingPolicies.Count | Should Be 0 }
    }

    It "rejects <Variant> instead of relying on the policy name in script <Script>" -TestCases @(
        foreach ($number in @("17", "99")) {
            foreach ($variant in @(
                "HighOnly", "UserRiskOnly", "GroupOnly", "OptionalMfa", "NoMfa", "BlockedGrant",
                "MissingFrequency", "PeriodicFrequency", "FrequencyDisabled", "SecondaryOnly",
                "MalformedFrequency"
            )) {
                @{ Script = $number; Variant = $variant }
            }
        }
    ) {
        param($Script, $Variant)
        switch ($Variant) {
            "HighOnly" { $script:policy.conditions.signInRiskLevels = @("high") }
            "UserRiskOnly" {
                $script:policy.conditions.signInRiskLevels = @()
                $script:policy.conditions.userRiskLevels = @("high")
            }
            "GroupOnly" {
                $script:policy.conditions.users.includeUsers = @()
                $script:policy.conditions.users.includeGroups = @("specific-group")
            }
            "OptionalMfa" { $script:policy.grantControls.builtInControls = @("compliantDevice") }
            "NoMfa" { $script:policy.grantControls.authenticationStrength = $null }
            "BlockedGrant" { $script:policy.grantControls.builtInControls = @("block") }
            "MissingFrequency" { $script:policy.Remove("sessionControls") }
            "PeriodicFrequency" { $script:policy.sessionControls.signInFrequency.frequencyInterval = "timeBased" }
            "FrequencyDisabled" { $script:policy.sessionControls.signInFrequency.isEnabled = $false }
            "SecondaryOnly" {
                $script:policy.sessionControls.signInFrequency.authenticationType = "secondaryAuthentication"
            }
            "MalformedFrequency" { $script:policy.sessionControls.signInFrequency.isEnabled = "true" }
        }
        $result = Invoke-SignInRiskPolicyCheck $Script
        $configuration = if ($Script -eq "17") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $false
        $configuration.Resolved | Should Be $false
    }

    It "reports an absent policy without null matching-name entries in script <Script>" -TestCases @(
        @{ Script = "17" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:data.ConditionalAccess = @()
        $result = Invoke-SignInRiskPolicyCheck $Script
        $configuration = if ($Script -eq "17") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $false
        $configuration.Policies.Count | Should Be 0
        if ($Script -eq "17") { $result.MatchingPolicies.Count | Should Be 0 }
    }

    It "surfaces a failed policy read in script <Script>" -TestCases @(
        @{ Script = "17" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:readFailures.ConditionalAccess = "Fixture policy read denied."
        { Invoke-SignInRiskPolicyCheck $Script } | Should Throw "Fixture policy read denied"
    }

    It "rejects <Field> on a matching policy in script <Script>" -TestCases @(
        foreach ($number in @("17", "99")) {
            foreach ($field in @("id", "displayName", "state")) {
                @{ Script = $number; Field = $field }
            }
        }
    ) {
        param($Script, $Field)
        $script:policy[$Field] = ""
        { Invoke-SignInRiskPolicyCheck $Script } | Should Throw "missing identity data or an unrecognized state"
    }

    It "accepts the Graph object representation in script <Script>" -TestCases @(
        @{ Script = "17" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:data.ConditionalAccess = @($script:policy | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
        (Invoke-SignInRiskPolicyCheck $Script -ApproveExclusions).Status | Should Be "IMPLEMENTED"
    }

    It "does not substitute Security Defaults for a sign-in risk policy" {
        $script:data.ConditionalAccess = @()
        $script:data.SecurityDefaults.isEnabled = $true
        $result = Invoke-SignInRiskPolicyCheck "99"
        $result.Status | Should Be "NOT-CONFIGURED"
        $result.PolicyConfiguration.SecurityDefaultsEnabled | Should Be $null
        $result.Evidence | Should Match "Security Defaults alone does not satisfy"
    }

    It "does not depend on unrelated Security Defaults or registration reads" {
        $script:readFailures.SecurityDefaults = "Fixture Security Defaults read failed."
        $script:readFailures.Registration = "Fixture registration read failed."
        (Invoke-SignInRiskPolicyCheck "99").Status | Should Be "IMPLEMENTED"
    }

    It "retains strict user-risk exclusion checking in script 99" {
        $script:policy.conditions.signInRiskLevels = @()
        $script:policy.conditions.userRiskLevels = @("high")
        $script:policy.grantControls.operator = "AND"
        $script:policy.grantControls.builtInControls = @("riskRemediation")
        (Get-RiskAssessment -Risk User).Status | Should Be "UNKNOWN"
        $script:approvedExclusions = @{ ApprovedExcludedUserIds = @($script:emergencyIds.Guid) }
        (Get-RiskAssessment -Risk User).Status | Should Be "IMPLEMENTED"
        $script:policy.sessionControls.signInFrequency.authenticationType = "secondaryAuthentication"
        (Get-RiskAssessment -Risk User).Status | Should Be "UNKNOWN"
    }

    It "persists risk levels and reauthentication settings in script 99 snapshots" {
        $result = Invoke-SignInRiskPolicyCheck "99"
        $path = Save-RecommendationSnapshot -Results @($result) `
            -TenantId $script:tenantId -CheckedAt ([datetimeoffset]::UtcNow) -Directory $TestDrive
        $saved = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
        $saved[0].PolicyConfiguration.PolicyFound | Should Be $true
        $saved[0].PolicyConfiguration.CoverageVerified | Should Be $false
        $saved[0].PolicyConfiguration.Policies[0].SignInRiskLevels.Count | Should Be 2
        $saved[0].PolicyConfiguration.Policies[0].SignInFrequency.AuthenticationType |
            Should Be "primaryAndSecondaryAuthentication"
    }

    It "supports sign-in risk assessment through the exported common-module helper" {
        $module = Import-Module (Join-Path $scriptsRoot "SecureM365.Common.psm1") `
            -Prefix RiskOffline -Force -PassThru -WarningAction SilentlyContinue
        try {
            $result = & $module.ExportedFunctions["Get-RiskOfflineSecureM365MfaPolicyAssessment"] `
                -SignInRisk -Policies @($script:policy)
            $result.Resolved | Should Be $true
            $result.CoverageVerified | Should Be $false
        }
        finally {
            Remove-Module $module -Force
        }
    }
}
