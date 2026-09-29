#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$scriptNames = @(
    "10-New-AdminMfaPolicy.ps1"
    "12-New-AllUserMfaPolicy.ps1"
    "14-New-BlockLegacyAuthenticationPolicy.ps1"
    "16-New-SignInRiskPolicy.ps1"
    "18-New-UserRiskPolicy.ps1"
)
$script:policyScripts = @{}
foreach ($name in $scriptNames) {
    $errors = $null
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $name), [ref] $null, [ref] $errors
    )
    if ($errors.Count -gt 0) { throw ($errors.Message -join "; ") }
    $statements = @($source.EndBlock.Statements | Where-Object {
        $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
        $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
        $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
    })
    $script:policyScripts[$name] = [scriptblock]::Create(
        ($source.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
        $source.ParamBlock.Extent.Text + "`n" + ($statements.Extent.Text -join "`n")
    )
}

function Connect-SecureM365Graph {
    param([guid] $TenantId, [string[]] $AdditionalScopes, [switch] $UseDeviceCode)
}
function Get-MgRoleManagementDirectoryRoleDefinition {
    param([switch] $All)
    @(
        "Global Administrator", "Application Administrator", "Authentication Administrator",
        "Authentication Policy Administrator", "Billing Administrator",
        "Cloud Application Administrator", "Conditional Access Administrator",
        "Exchange Administrator", "Helpdesk Administrator",
        "Identity Governance Administrator", "Password Administrator",
        "Privileged Authentication Administrator", "Privileged Role Administrator",
        "Security Administrator", "SharePoint Administrator", "User Administrator"
    ) | ForEach-Object {
        [pscustomobject]@{ DisplayName = $_; TemplateId = [guid]::NewGuid().Guid }
    }
}
function New-SecureM365ConditionalAccessPolicy {
    param([hashtable] $BodyParameter)
    [void] $script:createdBodies.Add($BodyParameter)
    [pscustomobject]@{
        Id = [guid]::NewGuid().Guid
        DisplayName = $BodyParameter.displayName
        State = $BodyParameter.state
    }
}

function Invoke-PolicyCreation {
    param(
        [Parameter(Mandatory)][string] $File,
        [switch] $ReportOnly,
        [switch] $WhatIf
    )

    $parameters = @{
        TenantId = [guid] "11111111-1111-4111-8111-111111111111"
        Confirm = $false
        ReportOnly = $ReportOnly
        WhatIf = $WhatIf
    }
    if ($File -ne "14-New-BlockLegacyAuthenticationPolicy.ps1") {
        $parameters.EmergencyAccessAccountId = @(
            [guid] "22222222-2222-4222-8222-222222222222"
            [guid] "33333333-3333-4333-8333-333333333333"
        )
    }
    & $script:policyScripts[$File] @parameters 6>&1
}

Describe "Conditional Access creation mode (offline)" {
    BeforeEach {
        $script:createdBodies = [System.Collections.Generic.List[hashtable]]::new()
    }

    foreach ($file in $scriptNames) {
        Context $file {
            It "creates an enforced policy by default" {
                Invoke-PolicyCreation -File $file | Out-Null
                $script:createdBodies.Count | Should Be 1
                $script:createdBodies[0].state | Should Be "enabled"
            }

            It "creates a report-only policy when requested" {
                Invoke-PolicyCreation -File $file -ReportOnly | Out-Null
                $script:createdBodies.Count | Should Be 1
                $script:createdBodies[0].state | Should Be "enabledForReportingButNotEnforced"
            }

            It "previews enforced creation without writing" {
                Invoke-PolicyCreation -File $file -WhatIf | Out-Null
                $script:createdBodies.Count | Should Be 0
                $scriptText = Get-Content (Join-Path $scriptsRoot $file) -Raw
                $scriptText | Should Match 'ShouldProcess\(\$TenantId\.Guid, "Create \$policyMode'
                $scriptText | Should Match '\{ "report-only" \} else \{ "enforced" \}'
            }

            It "previews report-only creation without writing" {
                Invoke-PolicyCreation -File $file -ReportOnly -WhatIf | Out-Null
                $script:createdBodies.Count | Should Be 0
                $scriptText = Get-Content (Join-Path $scriptsRoot $file) -Raw
                $scriptText | Should Match 'ShouldProcess\(\$TenantId\.Guid, "Create \$policyMode'
            }

            It "retains high-impact confirmation" {
                $source = [System.Management.Automation.Language.Parser]::ParseFile(
                    (Join-Path $scriptsRoot $file), [ref] $null, [ref] $null
                )
                $binding = $source.ParamBlock.Attributes |
                    Where-Object { $_.TypeName.Name -eq "CmdletBinding" }
                ($binding.NamedArguments |
                    Where-Object ArgumentName -eq "ConfirmImpact").Argument.SafeGetValue() |
                    Should Be "High"
            }
        }
    }

    It "does not change script 20's reviewed-policy behavior" {
        $script20 = Get-Content (Join-Path $scriptsRoot "20-Enable-ReviewedConditionalAccessPolicy.ps1") -Raw
        $script20 | Should Match 'enabledForReportingButNotEnforced'
        $script20 | Should Match 'Update-MgIdentityConditionalAccessPolicy'
    }
}
