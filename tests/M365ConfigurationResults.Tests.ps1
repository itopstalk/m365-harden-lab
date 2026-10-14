#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$scriptPath = Join-Path $scriptsRoot "ZZ-ConfigureM365Status.ps1"
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref] $null, [ref] $parseErrors
)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }

$configurationTry = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.TryStatementAst]
})
if ($configurationTry.Count -ne 1) { throw "Expected one configuration try block." }
$resultAssignment = @($configurationTry[0].Body.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -eq '$result'
})
if ($resultAssignment.Count -ne 1) { throw "Expected one final result assignment." }
$reportStatements = @($configurationTry[0].Body.Statements | Where-Object {
    $_.Extent.StartOffset -gt $resultAssignment[0].Extent.EndOffset
})
$reportScript = [scriptblock]::Create(
    ($reportStatements.Extent.Text -join [Environment]::NewLine)
)
$approvalGuard = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.IfStatementAst] -and
        $_.Extent.Text.Contains('$PSCmdlet.ShouldProcess(')
})
if ($approvalGuard.Count -ne 1) { throw "Expected one configuration approval guard." }
$previewReportScript = [scriptblock]::Create(
    '[CmdletBinding(SupportsShouldProcess)] param([switch] $PassThru)' +
    [Environment]::NewLine + $approvalGuard[0].Extent.Text +
    [Environment]::NewLine + $reportScript.ToString()
)

Describe "Standalone configuration final results" {
    BeforeEach {
        $script:targetTenantId = [guid] "11111111-1111-4111-8111-111111111111"
        $script:application = [pscustomobject]@{
            ApplicationId = "22222222-2222-4222-8222-222222222222"
            CertificateThumbprint = "0123456789012345678901234567890123456789"
        }
        $script:result = [pscustomobject]@{
            Status = "Configured"
            TenantId = $script:targetTenantId.Guid
            TeamsApplication = $script:application
            PasswordFilePath = "fixture-private-password-artifact"
            ConditionalAccessPolicies = @(
                [pscustomobject]@{
                    DisplayName = "CA001 - Require MFA for administrators"
                    State = "enabled"
                }
                [pscustomobject]@{
                    DisplayName = "CA002 - Require MFA for all users"
                    State = "enabled"
                }
            )
        }
        $script:runState = @{ CurrentOperation = "Verify final configuration" }
        $script:PassThru = $false
        $script:PasswordFilePath = $null
        $workingDirectory = Join-Path $TestDrive ("results [local] " + [guid]::NewGuid().Guid)
        $null = New-Item -Path $workingDirectory -ItemType Directory -ErrorAction Stop
        $script:expectedReportPath = Join-Path $workingDirectory "hardening-results.txt"
        $script:displayedResults = $null
        $script:existingReportAtDisplay = $null
        Push-Location -LiteralPath $workingDirectory
        Mock Write-Host {
            $script:displayedResults = [string] $Object
            if (Test-Path -LiteralPath $script:expectedReportPath -PathType Leaf) {
                $script:existingReportAtDisplay = Get-Content -LiteralPath $script:expectedReportPath -Raw
            }
        }
    }

    AfterEach {
        Pop-Location
    }

    It "displays and then saves only the final results in the working directory" {
        $output = @(& $reportScript)

        $output.Count | Should Be 0
        $script:existingReportAtDisplay | Should BeNullOrEmpty
        $saved = Get-Content -LiteralPath $script:expectedReportPath -Raw
        $saved | Should Be ($script:displayedResults + [Environment]::NewLine)
        $saved | Should Match "DisplayName\s+State"
        $saved | Should Match "CA001 - Require MFA for administrators"
        $saved | Should Match "CA002 - Require MFA for all users"
        $saved | Should Match "enabled"
        $saved | Should Match "Configuration completed: Configured"
        $saved | Should Match $script:targetTenantId.Guid
        $saved | Should Match $script:application.ApplicationId
        $saved | Should Match $script:application.CertificateThumbprint
        $saved | Should Match "Consent and all three Global Teams settings were read back"
        $saved | Should Not Match "configuration plan|WARNING:|fixture-private-password-artifact"
    }

    It "replaces the previous report only after displaying the new results" {
        [IO.File]::WriteAllText($script:expectedReportPath, "previous report")

        & $reportScript

        $script:existingReportAtDisplay | Should Be "previous report"
        $saved = Get-Content -LiteralPath $script:expectedReportPath -Raw
        $saved | Should Be ($script:displayedResults + [Environment]::NewLine)
        $saved | Should Not Match "previous report"
    }

    It "saves results from a completed report-only run" {
        $script:result.Status = "ReportOnlyRun"
        $script:result.ConditionalAccessPolicies[0].State = "enabledForReportingButNotEnforced"

        & $reportScript

        $saved = Get-Content -LiteralPath $script:expectedReportPath -Raw
        $saved | Should Match "Configuration completed: ReportOnlyRun"
        $saved | Should Match "enabledForReportingButNotEnforced"
    }

    It "preserves the structured PassThru result without adding text to the output stream" {
        $script:PassThru = $true

        $output = @(& $reportScript)

        $output.Count | Should Be 1
        [object]::ReferenceEquals($output[0], $script:result) | Should Be $true
        Test-Path -LiteralPath $script:expectedReportPath -PathType Leaf | Should Be $true
    }

    It "writes UTF-8 text without losing non-ASCII characters" {
        $name = "CA001 - Caf$([char] 0x00E9) MFA"
        $script:result.ConditionalAccessPolicies[0].DisplayName = $name

        & $reportScript

        $bytes = [IO.File]::ReadAllBytes($script:expectedReportPath)
        $saved = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $saved | Should Match $name
    }

    It "rejects a directory at the report path after displaying the results" {
        $null = New-Item -Path $script:expectedReportPath -ItemType Directory -ErrorAction Stop

        { & $reportScript } | Should Throw "is a directory"

        $script:displayedResults | Should Match "Configuration completed: Configured"
        $script:runState.CurrentOperation | Should Match "Save final configuration results"
    }

    It "propagates a report write failure after displaying the results" {
        Mock Set-Content { throw "Fixture report write denied." }

        { & $reportScript } | Should Throw "Fixture report write denied"

        $script:displayedResults | Should Match "Configuration completed: Configured"
        $script:runState.CurrentOperation | Should Match "Save final configuration results"
    }

    It "does not overwrite an emergency password artifact at the report path" {
        $script:PasswordFilePath = ".\hardening-results.txt"
        [IO.File]::WriteAllText($script:expectedReportPath, "fixture encrypted password artifact")

        { & $reportScript } | Should Throw "also PasswordFilePath"

        Get-Content -LiteralPath $script:expectedReportPath -Raw |
            Should Be "fixture encrypted password artifact"
    }

    It "returns the preview plan without displaying or writing final results under WhatIf" {
        $script:configurationPlan = [pscustomobject]@{ Status = "Planned" }
        $approvalGuard[0].Extent.StartOffset |
            Should BeLessThan $resultAssignment[0].Extent.StartOffset

        $output = @(& $previewReportScript -WhatIf -PassThru)

        $output.Count | Should Be 1
        [object]::ReferenceEquals($output[0], $script:configurationPlan) | Should Be $true
        $script:displayedResults | Should BeNullOrEmpty
        Test-Path -LiteralPath $script:expectedReportPath | Should Be $false
    }
}
