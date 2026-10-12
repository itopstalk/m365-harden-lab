#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"

function Get-UserRiskTestScriptBlock {
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

$script:createUserRiskPolicy = Get-UserRiskTestScriptBlock "18-New-UserRiskPolicy.ps1"
$script:testUserRiskPolicy = Get-UserRiskTestScriptBlock "19-Test-UserRiskPolicy.ps1"
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
                "Get-SecureM365GraphCollection", "Test-SecureM365CaTargetsAllUsers",
                "Test-SecureM365CaHasOnlyApprovedExclusions", "Test-SecureM365CaTargetsAllResources",
                "Test-SecureM365CaRequiresMfa", "Test-SecureM365CaPolicyScope",
                "Test-SecureM365CaUsesEveryTimeSignInFrequency", "Get-SecureM365MfaPolicyAssessment",
                "New-Assessment", "Get-CheckData", "Get-RiskAssessment", "Save-RecommendationSnapshot"
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
$checks = & ([scriptblock]::Create("$($checksAssignment.Extent.Text)`n`$checks"))
$script:userRiskReportCheck = @($checks | Where-Object {
    $_.Title -eq "Enable Microsoft Entra ID Identity Protection user risk policies"
})
if ($script:userRiskReportCheck.Count -ne 1) { throw "Expected exactly one user-risk recommendation." }
$script:userRiskReportCheck = $script:userRiskReportCheck[0]
$readersAssignment = $source.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $_.Left.Extent.Text -eq '$readers'
}
$script:userRiskReaders = & ([scriptblock]::Create("$($readersAssignment.Extent.Text)`n`$readers"))

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
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, [hashtable] $Headers)
    throw "Unmocked Graph request."
}
function Test-SecureM365ScoreAction {
    param([string] $Title, [string] $ControlName)
    throw "Secure Score must not determine user-risk policy presence."
}

function Invoke-UserRiskPolicyCheck {
    param([string] $Script, [switch] $ApproveExclusions)
    if ($Script -eq "19") {
        $parameters = @{ TenantId = $script:tenantId }
        if ($ApproveExclusions) { $parameters.ApprovedExcludedUserId = $script:emergencyIds }
        & $script:testUserRiskPolicy @parameters
    }
    else {
        if ($ApproveExclusions) {
            $script:approvedExclusions = @{ ApprovedExcludedUserIds = @($script:emergencyIds.Guid) }
        }
        if (-not $script:readFailures.ContainsKey("ConditionalAccess")) {
            $script:data.ConditionalAccess = @(& $script:userRiskReaders.ConditionalAccess)
        }
        & $script:userRiskReportCheck.Evaluate
    }
}

Describe "User-risk detection using script 18 and the real Graph readers (offline)" {
    BeforeEach {
        $script:tenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $script:emergencyIds = [guid[]] @(
            "22222222-2222-4222-8222-222222222222"
            "33333333-3333-4333-8333-333333333333"
        )
        $script:readFailures = @{}
        $script:approvedExclusions = @{}
        $script:data = @{ SecurityDefaults = @{ isEnabled = $false } }
        $script:useSecondPage = $false
        $script:objectResponse = $false
        Mock Connect-SecureM365Graph { [pscustomobject]@{ TenantId = $script:tenantId.Guid } }
        Mock New-SecureM365ConditionalAccessPolicy {
            param($BodyParameter)
            $script:policy = $BodyParameter + @{ id = "44444444-4444-4444-8444-444444444444" }
            $script:wirePolicies = @($script:policy)
            [pscustomobject] $script:policy
        }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Headers)
            if ($Method -ne "GET" -or $Uri -notlike "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies*") {
                throw "Unexpected Graph request: $Method $Uri"
            }
            if ($script:readFailures.ContainsKey("ConditionalAccess")) {
                throw $script:readFailures.ConditionalAccess
            }
            if ($script:useSecondPage -and $Uri -notlike "*skiptoken*") {
                return @{
                    value = @()
                    '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=fixture'
                }
            }
            $policies = @(ConvertTo-Json -InputObject @($script:wirePolicies) -Depth 20 |
                ConvertFrom-Json -AsHashtable)
            foreach ($policy in $policies) {
                if ($Headers.Prefer -ne "include-unknown-enum-members") {
                    $policy.grantControls.builtInControls = @($policy.grantControls.builtInControls | ForEach-Object {
                        if ($_ -eq "riskRemediation") { "unknownFutureValue" } else { $_ }
                    })
                }
            }
            if ($script:objectResponse) {
                $policies = @(ConvertTo-Json -InputObject $policies -Depth 20 | ConvertFrom-Json)
            }
            @{ value = $policies }
        }
        Mock Test-SecureM365ScoreAction { throw "Secure Score must not be read." }
        & $script:createUserRiskPolicy -TenantId $script:tenantId `
            -EmergencyAccessAccountId $script:emergencyIds -Confirm:$false | Out-Null
    }

    It "finds the unchanged script 18 policy despite emergency exclusions in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $results = @(Invoke-UserRiskPolicyCheck $Script)
        $results.Count | Should Be 1
        $result = $results[0]
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.PolicyFound | Should Be $true
        $configuration.EnabledPolicyFound | Should Be $true
        $configuration.Resolved | Should Be $true
        $configuration.CoverageVerified | Should Be $false
        $configuration.Policies.Count | Should Be 1
        $configuration.Policies[0].Id | Should Be $script:policy.id
        $configuration.Policies[0].DisplayName | Should Be "CA005 - Require remediation for high user risk"
        $configuration.Policies[0].RemediationControl | Should Be "passwordChange"
        $configuration.Policies[0].GrantOperator | Should Be "AND"
        $configuration.Policies[0].UserRiskLevels[0] | Should Be "high"
        $configuration.Policies[0].AuthenticationStrengthId | Should Be "00000000-0000-0000-0000-000000000002"
        $configuration.Policies[0].SignInFrequency.AuthenticationType | Should Be "primaryAndSecondaryAuthentication"
        $configuration.Policies[0].ExcludedUserIds.Count | Should Be 2
        $configuration.ExclusionEvidence | Should Match $script:emergencyIds[0].Guid
        if ($Script -eq "19") { $result.MatchingPolicies[0] | Should Be $script:policy.displayName }
        Assert-MockCalled Test-SecureM365ScoreAction -Times 0 -Scope It
    }

    It "uses approved exclusions only for coverage in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $result = Invoke-UserRiskPolicyCheck $Script -ApproveExclusions
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.CoverageVerified | Should Be $true
        $configuration.Policies[0].ExclusionsApproved | Should Be $true
    }

    It "reads modern remediation with the evolving-enum header on every page in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:policy.grantControls.builtInControls = @("riskRemediation")
        $script:useSecondPage = $true
        $result = Invoke-UserRiskPolicyCheck $Script
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.Policies[0].RemediationControl | Should Be "riskRemediation"
        Assert-MockCalled Invoke-MgGraphRequest -Times 2 -Scope It -ParameterFilter {
            $Headers.Prefer -eq "include-unknown-enum-members"
        }
        Assert-MockCalled Invoke-MgGraphRequest -Times 0 -Scope It -ParameterFilter {
            $Headers.Prefer -ne "include-unknown-enum-members"
        }
    }

    It "recognizes the documented legacy MFA/password-change combination in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:policy.grantControls.Remove("authenticationStrength")
        $script:policy.grantControls.builtInControls = @("mfa", "passwordChange")
        (Invoke-UserRiskPolicyCheck $Script).Status | Should Be "IMPLEMENTED"
    }

    It "reports <Restriction> as a coverage advisory in script <Script>" -TestCases @(
        foreach ($number in @("19", "99")) {
            foreach ($restriction in @("BrowserOnly", "Application", "Location", "SignInRisk")) {
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
            "SignInRisk" { $script:policy.conditions.signInRiskLevels = @("high") }
        }
        $result = Invoke-UserRiskPolicyCheck $Script -ApproveExclusions
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "IMPLEMENTED"
        $configuration.CoverageVerified | Should Be $false
    }

    It "does not pass a <State> policy in script <Script>" -TestCases @(
        foreach ($number in @("19", "99")) {
            foreach ($state in @("disabled", "enabledForReportingButNotEnforced")) {
                @{ Script = $number; State = $state }
            }
        }
    ) {
        param($Script, $State)
        $script:policy.state = $State
        $result = Invoke-UserRiskPolicyCheck $Script
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $true
        $configuration.EnabledPolicyFound | Should Be $false
        if ($Script -eq "19") { $result.MatchingPolicies.Count | Should Be 0 }
    }

    It "rejects <Variant> in script <Script>" -TestCases @(
        foreach ($number in @("19", "99")) {
            foreach ($variant in @(
                "MediumOnly", "SignInRiskOnly", "GroupOnly", "OptionalControls", "NoMfa",
                "NoRemediation", "BothRemediations", "ModernWithoutStrength", "ModernNonMfaStrength",
                "ModernMixedMfaGrants", "BlockedGrant", "MissingFrequency", "SecondaryOnly",
                "PeriodicFrequency", "MalformedFrequency", "UnknownRemediation"
            )) {
                @{ Script = $number; Variant = $variant }
            }
        }
    ) {
        param($Script, $Variant)
        switch ($Variant) {
            "MediumOnly" { $script:policy.conditions.userRiskLevels = @("medium") }
            "SignInRiskOnly" {
                $script:policy.conditions.userRiskLevels = @()
                $script:policy.conditions.signInRiskLevels = @("medium", "high")
            }
            "GroupOnly" {
                $script:policy.conditions.users.includeUsers = @()
                $script:policy.conditions.users.includeGroups = @("specific-group")
            }
            "OptionalControls" { $script:policy.grantControls.operator = "OR" }
            "NoMfa" { $script:policy.grantControls.Remove("authenticationStrength") }
            "NoRemediation" { $script:policy.grantControls.builtInControls = @() }
            "BothRemediations" { $script:policy.grantControls.builtInControls = @("passwordChange", "riskRemediation") }
            "ModernWithoutStrength" {
                $script:policy.grantControls.Remove("authenticationStrength")
                $script:policy.grantControls.builtInControls = @("mfa", "riskRemediation")
            }
            "ModernNonMfaStrength" {
                $script:policy.grantControls.builtInControls = @("riskRemediation")
                $script:policy.grantControls.authenticationStrength.id = "00000000-0000-0000-0000-000000000001"
            }
            "ModernMixedMfaGrants" { $script:policy.grantControls.builtInControls = @("mfa", "riskRemediation") }
            "BlockedGrant" { $script:policy.grantControls.builtInControls = @("passwordChange", "block") }
            "MissingFrequency" { $script:policy.Remove("sessionControls") }
            "SecondaryOnly" { $script:policy.sessionControls.signInFrequency.authenticationType = "secondaryAuthentication" }
            "PeriodicFrequency" { $script:policy.sessionControls.signInFrequency.frequencyInterval = "timeBased" }
            "MalformedFrequency" { $script:policy.sessionControls.signInFrequency.isEnabled = "true" }
            "UnknownRemediation" { $script:policy.grantControls.builtInControls = @("unknownFutureValue") }
        }
        $result = Invoke-UserRiskPolicyCheck $Script
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.PolicyFound | Should Be $false
        $configuration.Resolved | Should Be $false
    }

    It "returns an empty matching list when no policy exists in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:wirePolicies = @()
        $result = Invoke-UserRiskPolicyCheck $Script
        $configuration = if ($Script -eq "19") { $result } else { $result.PolicyConfiguration }
        $result.Status | Should Be "NOT-CONFIGURED"
        $configuration.Policies.Count | Should Be 0
        if ($Script -eq "19") { $result.MatchingPolicies.Count | Should Be 0 }
    }

    It "surfaces policy-read failures in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:readFailures.ConditionalAccess = "Fixture policy read denied."
        { Invoke-UserRiskPolicyCheck $Script } | Should Throw "Fixture policy read denied"
    }

    It "rejects malformed <Field> on a matching policy in script <Script>" -TestCases @(
        foreach ($number in @("19", "99")) {
            foreach ($field in @("id", "displayName", "state")) {
                @{ Script = $number; Field = $field }
            }
        }
    ) {
        param($Script, $Field)
        $script:policy[$Field] = ""
        { Invoke-UserRiskPolicyCheck $Script } | Should Throw "missing identity data or an unrecognized state"
    }

    It "accepts Graph object responses in script <Script>" -TestCases @(
        @{ Script = "19" }
        @{ Script = "99" }
    ) {
        param($Script)
        $script:objectResponse = $true
        (Invoke-UserRiskPolicyCheck $Script -ApproveExclusions).Status | Should Be "IMPLEMENTED"
    }

    It "does not substitute Security Defaults or depend on registration data" {
        $script:readFailures.SecurityDefaults = "Fixture Security Defaults read failed."
        $script:readFailures.Registration = "Fixture registration read failed."
        (Invoke-UserRiskPolicyCheck "99").Status | Should Be "IMPLEMENTED"
        $script:wirePolicies = @()
        $script:data.SecurityDefaults.isEnabled = $true
        $result = Invoke-UserRiskPolicyCheck "99"
        $result.Status | Should Be "NOT-CONFIGURED"
        $result.PolicyConfiguration.SecurityDefaultsEnabled | Should Be $null
        $result.Evidence | Should Match "Security Defaults alone does not satisfy"
    }

    It "persists user-risk and remediation details in script 99 snapshots" {
        $result = Invoke-UserRiskPolicyCheck "99"
        $path = Save-RecommendationSnapshot -Results @($result) `
            -TenantId $script:tenantId -CheckedAt ([datetimeoffset]::UtcNow) -Directory $TestDrive
        $saved = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
        $saved[0].PolicyConfiguration.PolicyFound | Should Be $true
        $saved[0].PolicyConfiguration.CoverageVerified | Should Be $false
        $saved[0].PolicyConfiguration.Policies[0].UserRiskLevels[0] | Should Be "high"
        $saved[0].PolicyConfiguration.Policies[0].RemediationControl | Should Be "passwordChange"
        $saved[0].PolicyConfiguration.Policies[0].SignInFrequency.AuthenticationType |
            Should Be "primaryAndSecondaryAuthentication"
    }

    It "supports user-risk assessment through the exported common-module helper" {
        $module = Import-Module (Join-Path $scriptsRoot "SecureM365.Common.psm1") `
            -Prefix UserRiskOffline -Force -PassThru -WarningAction SilentlyContinue
        try {
            $result = & $module.ExportedFunctions["Get-UserRiskOfflineSecureM365MfaPolicyAssessment"] `
                -UserRisk -Policies @($script:policy)
            $result.Resolved | Should Be $true
            $result.CoverageVerified | Should Be $false
        }
        finally {
            Remove-Module $module -Force
        }
    }
}
