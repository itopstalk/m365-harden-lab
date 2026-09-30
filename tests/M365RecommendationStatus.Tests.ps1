#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$scriptPath = Join-Path $scriptsRoot "99-Test-M365RecommendationStatus.ps1"
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref] $null, [ref] $parseErrors
)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }

foreach ($statement in $ast.EndBlock.Statements) {
    if (
        $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $statement.Name -in @(
            "New-Assessment"
            "Get-CheckData"
            "Get-CheckedSecurityDefaults"
            "Get-RegistrationCoverage"
            "Get-MfaAssessment"
            "Get-SsprAssessment"
        )
    ) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}

function Test-ReportPolicyScope { $true }
function Test-ReportMfaGrant { $true }
function Test-SecureM365CaTargetsAllUsers { $true }

Describe "Script 99 MFA enforcement assessment" {
    BeforeEach {
        $script:readFailures = @{}
        $script:data = @{
            SecurityDefaults = @{ isEnabled = $false }
            ConditionalAccess = @(
                @{
                    displayName = "Enforced MFA"
                    state = "enabled"
                    conditions = @{ users = @{ includeUsers = @("All") } }
                    grantControls = @{ builtInControls = @("mfa") }
                }
            )
            Users = @(
                @{
                    id = "11111111-1111-4111-8111-111111111111"
                    accountEnabled = $true
                    userType = "Member"
                }
            )
            Registration = @(
                @{
                    id = "11111111-1111-4111-8111-111111111111"
                    isAdmin = $true
                    isMfaCapable = $false
                    isSsprRegistered = $false
                    isSsprCapable = $false
                }
            )
            RoleAssignments = @()
        }
        $script:SsprAllScopeConfirmed = $false
    }

    It "reports enforced all-user MFA implemented despite incomplete registration" {
        $result = Get-MfaAssessment
        $result.Status | Should Be "IMPLEMENTED"
        $result.Details | Should Match "policy enforcement is verified"
        $result.Details | Should Match "not reported MFA-capable"
        $result.Details | Should Match "36 hours"
    }

    It "reports enforced administrator MFA implemented when registration is unavailable" {
        $script:readFailures["Registration"] = "fixture report unavailable"
        $result = Get-MfaAssessment -Administrators
        $result.Status | Should Be "IMPLEMENTED"
        $result.Details | Should Match "Policy enforcement remains verified"
        $result.Details | Should Match "fixture report unavailable"
    }

    It "still reports missing policy enforcement as not configured" {
        $script:data.ConditionalAccess = @()
        $result = Get-MfaAssessment
        $result.Status | Should Be "NOT-CONFIGURED"
    }

    It "exposes evidence while retaining the details compatibility property" {
        $result = New-Assessment "IMPLEMENTED" "fixture evidence"
        $result.Evidence | Should Be "fixture evidence"
        $result.Details | Should Be $result.Evidence
    }
}

Describe "Script 99 SSPR policy assessment" {
    BeforeEach {
        $script:readFailures = @{}
        $script:data = @{
            Users = @(
                @{
                    id = "11111111-1111-4111-8111-111111111111"
                    accountEnabled = $true
                    userType = "Member"
                }
                @{
                    id = "22222222-2222-4222-8222-222222222222"
                    accountEnabled = $true
                    userType = "Member"
                }
            )
            Registration = @(
                @{
                    id = "11111111-1111-4111-8111-111111111111"
                    isSsprEnabled = $true
                    isSsprRegistered = $true
                    isSsprCapable = $true
                }
                @{
                    id = "22222222-2222-4222-8222-222222222222"
                    isSsprEnabled = $false
                    isSsprRegistered = $false
                    isSsprCapable = $false
                }
            )
        }
        $script:SsprAllScopeConfirmed = $false
    }

    It "reports unknown when the built-in All-scope confirmation is disabled" {
        $result = Get-SsprAssessment
        $result.Status | Should Be "UNKNOWN"
        $result.Evidence | Should Match "has not been operator-confirmed"
        $result.Evidence | Should Match "1 of 2 enabled member accounts are reported SSPR-registered"
    }

    It "uses All-scope confirmation as authoritative and makes registration advisory" {
        $script:SsprAllScopeConfirmed = $true
        $result = Get-SsprAssessment
        $result.Status | Should Be "IMPLEMENTED"
        $result.Evidence | Should Match "recorded as operator-confirmed by the script default"
        $result.Evidence | Should Match "1 are not registered"
        $result.Evidence | Should Match "1 are not capable"
    }

    It "preserves confirmed implementation when registration data is unavailable" {
        $script:SsprAllScopeConfirmed = $true
        $script:readFailures["Registration"] = "fixture report unavailable"
        $result = Get-SsprAssessment
        $result.Status | Should Be "IMPLEMENTED"
        $result.Evidence | Should Match "readiness data could not be verified"
        $result.Evidence | Should Match "fixture report unavailable"
    }

    It "adds Evidence to the displayed and pass-through result shapes" {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match "\[switch\]\s*\`$SsprAllScopeConfirmed\s*=\s*\`$true"
        $source | Should Match "Format-Table Number, Status, Recommendation, Evidence -Wrap"
        $source | Should Match "Evidence\s*=\s*\`$assessment\.Evidence"
    }
}
