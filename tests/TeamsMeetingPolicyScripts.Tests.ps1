#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$script:mutatorCases = @(
    @{ File = "40-Set-TeamsInvitedUsersLobbyPolicy.ps1"; Property = "AutoAdmittedUsers"; Expected = "InvitedUsers" }
    @{ File = "42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1"; Property = "DesignatedPresenterRoleMode"; Expected = "OrganizerOnlyUserOverride" }
    @{ File = "44-Disable-TeamsAnonymousMeetingJoin.ps1"; Property = "AllowAnonymousUsersToJoinMeeting"; Expected = $false }
)
$script:validatorCases = @(
    @{ File = "41-Test-TeamsInvitedUsersLobbyPolicy.ps1"; Property = "AutoAdmittedUsers"; Expected = "InvitedUsers" }
    @{ File = "43-Test-TeamsOrganizerOnlyPresenterPolicy.ps1"; Property = "DesignatedPresenterRoleMode"; Expected = "OrganizerOnlyUserOverride" }
    @{ File = "45-Test-TeamsAnonymousMeetingJoin.ps1"; Property = "AllowAnonymousUsersToJoinMeeting"; Expected = $false }
)
$script:allScriptCases = @($script:mutatorCases) + @($script:validatorCases)
$script:scriptBlocks = @{}
$script:scriptSources = @{}
foreach ($case in $script:allScriptCases) {
    $parseErrors = $null
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $case.File), [ref] $null, [ref] $parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }
    $script:scriptSources[$case.File] = $source
    $statements = @($source.EndBlock.Statements | Where-Object {
        $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
        $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
        $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
    })
    $script:scriptBlocks[$case.File] = [scriptblock]::Create(
        ($source.ParamBlock.Attributes.Extent.Text -join "`n") + "`n" +
        $source.ParamBlock.Extent.Text + "`n" + ($statements.Extent.Text -join "`n")
    )
}

foreach ($name in @("SecureM365.Common.psm1", "99-Test-M365RecommendationStatus.ps1")) {
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $name), [ref] $null, [ref] $null
    )
    foreach ($statement in $source.EndBlock.Statements) {
        if (
            $statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $statement.Name -in @(
                "Connect-SecureM365Teams", "Get-SecureM365TeamsMeetingPolicy",
                "Get-SecureM365TeamsMeetingPolicyUpdateError",
                "New-Assessment", "Get-CheckData", "Get-TeamsAssessment"
            )
        ) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }
}

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
function Connect-SecureM365Graph { [CmdletBinding()] param([guid] $TenantId, [switch] $UseDeviceCode) throw "Unmocked Graph connection." }
function Test-SecureM365ScoreAction { [CmdletBinding()] param([string] $Title, [string] $ControlName) throw "Unmocked score read." }
function Get-CsTeamsMeetingPolicy {
    [CmdletBinding()]
    param([string] $Identity)
    throw "Unmocked meeting policy read."
}
function Set-CsTeamsMeetingPolicy {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [string] $AutoAdmittedUsers,
        [string] $DesignatedPresenterRoleMode,
        [bool] $AllowAnonymousUsersToJoinMeeting
    )
    throw "Unmocked meeting policy update."
}

function Invoke-TeamsScript {
    param([string] $File, [hashtable] $Parameters = @{})
    $ErrorActionPreference = "Stop"
    if ($File -in @($script:mutatorCases.File)) {
        & $script:scriptBlocks[$File] -TenantId ([guid] $script:fixture.TenantId) -Confirm:$false @Parameters
    }
    else {
        & $script:scriptBlocks[$File] -TenantId ([guid] $script:fixture.TenantId) @Parameters
    }
}

Describe "Global Teams meeting policy scope (offline)" {
    BeforeEach {
        $script:fixture = @{
            TenantId = "11111111-1111-4111-8111-111111111111"
            Global = [pscustomobject]@{
                Identity = "Global"
                AutoAdmittedUsers = "Everyone"
                DesignatedPresenterRoleMode = "EveryoneUserOverride"
                AllowAnonymousUsersToJoinMeeting = $true
            }
            ResponseMode = "Global"
            Reads = [System.Collections.Generic.List[string]]::new()
            Writes = [System.Collections.Generic.List[object]]::new()
            Connections = 0
            GraphConnections = 0
            ScoreReads = 0
            DeviceAuthentication = $false
            ApplicationId = $null
            CertificateThumbprint = $null
        }
        Mock Connect-MicrosoftTeams {
            param($TenantId, $UseDeviceAuthentication, $ApplicationId, $CertificateThumbprint, $Certificate)
            $script:fixture.Connections++
            $script:fixture.DeviceAuthentication = [bool] $UseDeviceAuthentication
            $script:fixture.ApplicationId = [string] $ApplicationId
            $script:fixture.CertificateThumbprint = [string] $CertificateThumbprint
            [pscustomobject]@{ TenantId = $TenantId; Account = "lab-admin@example.com" }
        }
        Mock Disconnect-MicrosoftTeams {}
        Mock Connect-SecureM365Graph {
            $script:fixture.GraphConnections++
            [pscustomobject]@{ TenantId = $script:fixture.TenantId; Environment = "Global" }
        }
        Mock Test-SecureM365ScoreAction { [void] $script:fixture.ScoreReads++ }
        Mock Get-CsTeamsMeetingPolicy {
            param($Identity)
            [void] $script:fixture.Reads.Add([string] $Identity)
            switch ($script:fixture.ResponseMode) {
                "Zero" { return }
                "Multiple" {
                    $script:fixture.Global.PSObject.Copy()
                    $script:fixture.Global.PSObject.Copy()
                }
                "Wrong" {
                    $wrong = $script:fixture.Global.PSObject.Copy()
                    $wrong.Identity = "Tag:AllOn"
                    $wrong
                }
                default { $script:fixture.Global.PSObject.Copy() }
            }
        }
        Mock Set-CsTeamsMeetingPolicy {
            param($Identity, $AutoAdmittedUsers, $DesignatedPresenterRoleMode, $AllowAnonymousUsersToJoinMeeting)
            if ($Identity -ne "Global") { throw "Unexpected update target '$Identity'." }
            $updates = @{}
            if ($null -ne $AutoAdmittedUsers) { $updates.AutoAdmittedUsers = $AutoAdmittedUsers }
            if ($null -ne $DesignatedPresenterRoleMode) { $updates.DesignatedPresenterRoleMode = $DesignatedPresenterRoleMode }
            if ($null -ne $AllowAnonymousUsersToJoinMeeting) { $updates.AllowAnonymousUsersToJoinMeeting = $AllowAnonymousUsersToJoinMeeting }
            if ($updates.Count -ne 1) { throw "Expected exactly one setting." }
            foreach ($property in $updates.Keys) {
                $script:fixture.Global.$property = $updates[$property]
                [void] $script:fixture.Writes.Add([pscustomobject]@{
                    Identity = $Identity
                    Property = $property
                    Value = $updates[$property]
                })
            }
        }
    }

    It "updates only Global and returns read-back evidence in <File>" -TestCases $script:mutatorCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-TeamsScript $File)
        $result.Count | Should Be 1
        $result[0].Identity | Should Be "Global"
        $result[0].$Property | Should Be $Expected
        $script:fixture.Writes.Count | Should Be 1
        $script:fixture.Writes[0].Identity | Should Be "Global"
        ($script:fixture.Reads -join ",") | Should Be "Global,Global"
    }

    It "keeps WhatIf read-only while returning Global evidence in <File>" -TestCases $script:mutatorCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-TeamsScript $File @{ WhatIf = $true })
        $result.Count | Should Be 1
        $result[0].Identity | Should Be "Global"
        $result[0].$Property | Should Not Be $Expected
        $script:fixture.Writes.Count | Should Be 0
        ($script:fixture.Reads -join ",") | Should Be "Global,Global"
    }

    It "does not rewrite an already compliant Global policy in <File>" -TestCases $script:mutatorCases {
        param($File, $Property, $Expected)
        $script:fixture.Global.$Property = $Expected
        $result = @(Invoke-TeamsScript $File)
        $result[0].Identity | Should Be "Global"
        $script:fixture.Writes.Count | Should Be 0
    }

    It "preserves high-impact ShouldProcess in <File>" -TestCases $script:mutatorCases {
        param($File, $Property, $Expected)
        $binding = $script:scriptSources[$File].ParamBlock.Attributes |
            Where-Object { $_.TypeName.Name -eq "CmdletBinding" }
        ($binding.NamedArguments | Where-Object ArgumentName -eq "SupportsShouldProcess").Argument.SafeGetValue() | Should Be $true
        ($binding.NamedArguments | Where-Object ArgumentName -eq "ConfirmImpact").Argument.SafeGetValue() | Should Be "High"
    }

    It "returns clear Global evidence from <File>" -TestCases $script:validatorCases {
        param($File, $Property, $Expected)
        $script:fixture.Global.$Property = $Expected
        $result = @(Invoke-TeamsScript $File)
        $evidence = @($result | Where-Object { $_.PSObject.Properties.Name -contains "PolicyIdentity" })[0]
        $evidence.PolicyIdentity | Should Be "Global"
        $evidence.ActualValue | Should Be $Expected
        $evidence.ExpectedValue | Should Be $Expected
        $evidence.Resolved | Should Be $true
        ($script:fixture.Reads -join ",") | Should Be "Global"
    }

    It "reports noncompliant Global evidence from <File>" -TestCases $script:validatorCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-TeamsScript $File)
        $evidence = @($result | Where-Object { $_.PSObject.Properties.Name -contains "PolicyIdentity" })[0]
        $evidence.PolicyIdentity | Should Be "Global"
        $evidence.Resolved | Should Be $false
    }

    It "fails before writes when Global retrieval returns zero policies in <File>" -TestCases $script:allScriptCases {
        param($File, $Property, $Expected)
        $script:fixture.ResponseMode = "Zero"
        { Invoke-TeamsScript $File } | Should Throw "exactly one Global"
        $script:fixture.Writes.Count | Should Be 0
    }

    It "fails before writes when Global retrieval returns multiple policies in <File>" -TestCases $script:allScriptCases {
        param($File, $Property, $Expected)
        $script:fixture.ResponseMode = "Multiple"
        { Invoke-TeamsScript $File } | Should Throw "returned 2"
        $script:fixture.Writes.Count | Should Be 0
    }

    It "fails before writes when Global retrieval returns the wrong identity in <File>" -TestCases $script:allScriptCases {
        param($File, $Property, $Expected)
        $script:fixture.ResponseMode = "Wrong"
        { Invoke-TeamsScript $File } | Should Throw "when Global was requested"
        $script:fixture.Writes.Count | Should Be 0
    }

    It "routes certificate application authentication in <File>" -TestCases $script:allScriptCases {
        param($File, $Property, $Expected)
        $appId = "55555555-5555-4555-8555-555555555555"
        $thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        $null = Invoke-TeamsScript $File @{
            TeamsApplicationId = [guid] $appId
            TeamsCertificateThumbprint = $thumbprint
        }
        $script:fixture.ApplicationId | Should Be $appId
        $script:fixture.CertificateThumbprint | Should Be $thumbprint
        $script:fixture.DeviceAuthentication | Should Be $false
    }

    It "ignores Tag policies when retrieving and assessing Global" {
        $tagPolicy = [pscustomobject]@{
            Identity = "Tag:AllOn"
            AutoAdmittedUsers = "Everyone"
            DesignatedPresenterRoleMode = "EveryoneUserOverride"
            AllowAnonymousUsersToJoinMeeting = $true
        }
        $data = @{ Teams = @($script:fixture.Global, $tagPolicy)[0] }
        $readFailures = @{}
        $script:fixture.Global.AutoAdmittedUsers = "InvitedUsers"
        $assessment = Get-TeamsAssessment -Property AutoAdmittedUsers -Expected "InvitedUsers"
        $assessment.Status | Should Be "IMPLEMENTED"
        $assessment.Details | Should Match "Global"
        $assessment.Details | Should Not Match "Tag:"
    }

    It "reports script 99 evidence identifying Global" {
        $data = @{ Teams = $script:fixture.Global }
        $readFailures = @{}
        $assessment = Get-TeamsAssessment -Property AutoAdmittedUsers -Expected "InvitedUsers"
        $assessment.Status | Should Be "NOT-CONFIGURED"
        $assessment.Details | Should Match "Global"
        $assessment.Details | Should Match "Everyone"
    }

    It "uses the exact Global helper in script 99 without an inventory read" {
        $sourceText = Get-Content -LiteralPath (Join-Path $scriptsRoot "99-Test-M365RecommendationStatus.ps1") -Raw
        $sourceText | Should Match "Get-SecureM365TeamsMeetingPolicy"
        $sourceText | Should Not Match "Get-CsTeamsMeetingPolicy\s+-ErrorAction"
    }

    It "never falls back to delegated authentication when certificate application auth is incomplete" {
        {
            Connect-SecureM365Teams `
                -TenantId ([guid] $script:fixture.TenantId) `
                -ApplicationId "55555555-5555-4555-8555-555555555555"
        } | Should Throw "exactly one"
        $script:fixture.Connections | Should Be 0
    }
}
