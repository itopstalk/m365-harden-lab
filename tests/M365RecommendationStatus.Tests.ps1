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
            "Save-RecommendationSnapshot"
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

Describe "Script 99 recommendation inventory" {
    It "contains ten recommendations without the role-baseline check" {
        $assignment = @(
            $ast.FindAll(
                {
                    param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $node.Left.Extent.Text -eq '$checks'
                },
                $true
            )
        )
        $assignment.Count | Should Be 1

        $checks = & ([scriptblock]::Create(
            "$($assignment[0].Extent.Text)`n`$checks"
        ))
        $checks.Count | Should Be 10
        $checks[9].Title | Should Be "Ensure 'Self service password reset enabled' is set to 'All'"
        @(
            $checks | Where-Object {
                $_.Title -eq "Use least privileged administrative roles"
            }
        ).Count | Should Be 0
        @(
            $ast.ParamBlock.Parameters | Where-Object {
                $_.Name.VariablePath.UserPath -eq "ApprovedBaselinePath"
            }
        ).Count | Should Be 0
    }
}

Describe "Script 99 snapshot persistence" {
    BeforeEach {
        $script:tenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $script:checkedAt = [datetimeoffset] "2026-09-29T21:24:25-07:00"
        $script:results = @(
            [pscustomobject]@{
                Number = 1
                Recommendation = "Fixture recommendation"
                Status = "IMPLEMENTED"
                Evidence = "Fixture evidence"
                Details = "Fixture evidence"
                TenantId = $script:tenantId.Guid
                CheckedAt = $script:checkedAt
            }
        )
    }

    It "creates a missing directory and writes a timestamped tenant snapshot" {
        $directory = Join-Path $TestDrive "snapshots"
        $snapshotPath = Save-RecommendationSnapshot `
            -Results $script:results `
            -TenantId $script:tenantId `
            -CheckedAt $script:checkedAt `
            -Directory $directory

        Test-Path -LiteralPath $directory -PathType Container | Should Be $true
        Split-Path -Leaf $snapshotPath |
            Should Be "11111111-1111-4111-8111-111111111111-m365-recommendation-status-20260930-042425000Z.json"
        $saved = @(Get-Content -LiteralPath $snapshotPath -Raw | ConvertFrom-Json)
        $saved.Count | Should Be 1
        $saved[0].Status | Should Be "IMPLEMENTED"
        $saved[0].Evidence | Should Be "Fixture evidence"
    }

    It "rejects a snapshot directory path that is an existing file" {
        $path = Join-Path $TestDrive "snapshot-file-path"
        [IO.File]::WriteAllText($path, "fixture")
        Test-Path -LiteralPath $path -PathType Leaf | Should Be $true

        $errorMessage = try {
            Save-RecommendationSnapshot `
                -Results $script:results `
                -TenantId $script:tenantId `
                -CheckedAt $script:checkedAt `
                -Directory $path
            $null
        }
        catch {
            $_.Exception.Message
        }
        $errorMessage | Should Match "exists but is not a directory"
    }

    It "does not overwrite an existing snapshot" {
        $directory = Join-Path $TestDrive "no-overwrite"
        $null = Save-RecommendationSnapshot `
            -Results $script:results `
            -TenantId $script:tenantId `
            -CheckedAt $script:checkedAt `
            -Directory $directory

        $errorMessage = try {
            Save-RecommendationSnapshot `
                -Results $script:results `
                -TenantId $script:tenantId `
                -CheckedAt $script:checkedAt `
                -Directory $directory
            $null
        }
        catch {
            $_.Exception.Message
        }
        $errorMessage | Should Match "already exists and will not be overwritten"
    }
}
