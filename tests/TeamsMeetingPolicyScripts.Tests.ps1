#Requires -Version 7.2

$scriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts"
$script:policyCases = @(
    @{ File = "40-Set-TeamsInvitedUsersLobbyPolicy.ps1"; Property = "AutoAdmittedUsers"; Expected = "InvitedUsers" }
    @{ File = "42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1"; Property = "DesignatedPresenterRoleMode"; Expected = "OrganizerOnlyUserOverride" }
    @{ File = "44-Disable-TeamsAnonymousMeetingJoin.ps1"; Property = "AllowAnonymousUsersToJoinMeeting"; Expected = $false }
)
$script:readOnlyCases = @(
    foreach ($case in $script:policyCases) {
        foreach ($source in @("Exception", "ErrorDetails")) {
            @{ File = $case.File; Property = $case.Property; Expected = $case.Expected; ErrorSource = $source }
        }
    }
)
$script:policyScripts = @{}
$script:policySources = @{}
foreach ($case in $script:policyCases) {
    $parseErrors = $null
    $source = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot $case.File), [ref] $null, [ref] $parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join "; ") }
    $script:policySources[$case.File] = $source
    # Keep production parameter binding and bodies, but never import service modules.
    $statements = @($source.EndBlock.Statements | Where-Object {
        $_ -isnot [System.Management.Automation.Language.PipelineAst] -or
        $_.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
        $_.PipelineElements[0].GetCommandName() -ne "Import-Module"
    })
    $script:policyScripts[$case.File] = [scriptblock]::Create(
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
    param([string] $TenantId, [switch] $UseDeviceAuthentication)
    throw "Unmocked Teams connection."
}
function Disconnect-MicrosoftTeams { [CmdletBinding()] param() throw "Unmocked Teams disconnect." }
function Get-CsTeamsMeetingPolicy {
    [CmdletBinding()]
    param([string] $Identity)
    throw "Unmocked meeting policy read."
}
function Set-CsTeamsMeetingPolicy {
    [CmdletBinding()]
    param([string] $Identity, [string] $AutoAdmittedUsers, [string] $DesignatedPresenterRoleMode, [bool] $AllowAnonymousUsersToJoinMeeting)
    throw "Unmocked meeting policy update."
}
function Invoke-PolicyScript {
    param([string] $File, [hashtable] $Parameters = @{})
    $ErrorActionPreference = "Stop"
    & $script:policyScripts[$File] -TenantId ([guid] $script:fixture.TenantId) -Confirm:$false @Parameters
}

Describe "Teams meeting policy target selection (offline)" {
    BeforeEach {
        $script:fixture = @{
            TenantId = "11111111-1111-4111-8111-111111111111"
            Policies = @(
                foreach ($identity in @(
                    "Global", "Tag:LabMeetings", "Tag:ExternalMeetings", "Tag:InternalMeetings",
                    "Tag:Training", "Tag:Events", "Tag:KioskCustom"
                )) {
                    [pscustomobject]@{
                        Identity = $identity
                        AutoAdmittedUsers = "Everyone"
                        DesignatedPresenterRoleMode = "EveryoneUserOverride"
                        AllowAnonymousUsersToJoinMeeting = $true
                    }
                }
            )
            Reads = [System.Collections.Generic.List[string]]::new()
            Writes = [System.Collections.Generic.List[object]]::new()
            Attempts = [System.Collections.Generic.List[string]]::new()
            Connections = 0
            Disconnected = $false
            DeviceAuthentication = $false
            WrongTenant = $false
            FailEnumeration = $false
            RejectIdentity = $null
            RejectError = $null
            WrongReadIdentity = $false
        }
        Mock Connect-MicrosoftTeams {
            param($TenantId, $UseDeviceAuthentication)
            $script:fixture.Connections++
            $script:fixture.DeviceAuthentication = [bool] $UseDeviceAuthentication
            [pscustomobject]@{
                TenantId = if ($script:fixture.WrongTenant) { "22222222-2222-4222-8222-222222222222" } else { $TenantId }
                Account = "lab-admin@example.com"
            }
        }
        Mock Disconnect-MicrosoftTeams { $script:fixture.Disconnected = $true }
        Mock Get-CsTeamsMeetingPolicy {
            param($Identity)
            [void] $script:fixture.Reads.Add([string] $Identity)
            if (-not $Identity) {
                if ($script:fixture.FailEnumeration) { throw "Meeting policy enumeration failed." }
                $script:fixture.Policies | ForEach-Object { $_.PSObject.Copy() }
            }
            else {
                $canonical = if ($Identity -eq "Global") { "Global" } else { "Tag:" + ($Identity -replace '^Tag:', '') }
                if ($script:fixture.WrongReadIdentity) { $canonical = "Global" }
                $script:fixture.Policies |
                    Where-Object Identity -eq $canonical |
                    ForEach-Object { $_.PSObject.Copy() }
            }
        }
        Mock Set-CsTeamsMeetingPolicy {
            param($Identity, $AutoAdmittedUsers, $DesignatedPresenterRoleMode, $AllowAnonymousUsersToJoinMeeting)
            [void] $script:fixture.Attempts.Add($Identity)
            if ($Identity -eq $script:fixture.RejectIdentity) {
                if ($null -ne $script:fixture.RejectError) { throw $script:fixture.RejectError }
                throw "Teams rejected update to policy '$Identity'."
            }
            $updates = @{}
            if ($null -ne $AutoAdmittedUsers) { $updates.AutoAdmittedUsers = $AutoAdmittedUsers }
            if ($null -ne $DesignatedPresenterRoleMode) { $updates.DesignatedPresenterRoleMode = $DesignatedPresenterRoleMode }
            if ($null -ne $AllowAnonymousUsersToJoinMeeting) { $updates.AllowAnonymousUsersToJoinMeeting = $AllowAnonymousUsersToJoinMeeting }
            if ($updates.Count -ne 1) { throw "Expected exactly one meeting policy setting per update." }
            $policy = @($script:fixture.Policies | Where-Object Identity -eq $Identity)
            if ($policy.Count -ne 1) { throw "Unexpected policy update target '$Identity'." }
            foreach ($property in $updates.Keys) {
                $policy[0].$property = $updates[$property]
                [void] $script:fixture.Writes.Add(@{ Identity = $Identity; Property = $property; Value = $updates[$property] })
            }
        }
    }

    It "updates every returned policy by default in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-PolicyScript $File)
        $result.Count | Should Be 7
        $script:fixture.Writes.Count | Should Be 7
        @($script:fixture.Policies | Where-Object { $_.$Property -ne $Expected }).Count | Should Be 0
        $script:fixture.Reads[0] | Should Be ""
        $script:fixture.Reads.Count | Should Be 8
    }

    It "restricts updates to Global when explicitly selected in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-PolicyScript $File @{ PolicyIdentity = @("Global") })
        $result.Count | Should Be 1
        $result[0].Identity | Should Be "Global"
        $result[0].$Property | Should Be $Expected
        $script:fixture.Writes.Count | Should Be 1
        $script:fixture.Writes[0].Identity | Should Be "Global"
        @($script:fixture.Policies | Where-Object { $_.$Property -eq $Expected }).Count | Should Be 1
    }

    It "updates only explicitly selected identities in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-PolicyScript $File @{ PolicyIdentity = @("LabMeetings", "Tag:KioskCustom") })
        $result.Count | Should Be 2
        ($script:fixture.Writes.Identity -join ",") | Should Be "Tag:LabMeetings,Tag:KioskCustom"
        @($result | Where-Object { $_.$Property -ne $Expected }).Count | Should Be 0
        $script:fixture.Policies[0].$Property | Should Not Be $Expected
    }

    It "updates every returned policy with AllPolicies in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-PolicyScript $File @{ AllPolicies = $true })
        $result.Count | Should Be 7
        $script:fixture.Writes.Count | Should Be 7
        @($script:fixture.Policies | Where-Object { $_.$Property -ne $Expected }).Count | Should Be 0
        $script:fixture.Reads[0] | Should Be ""
        $script:fixture.Reads.Count | Should Be 8
    }

    It "keeps WhatIf read-only for the default all-policy scope in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $result = @(Invoke-PolicyScript $File @{ WhatIf = $true })
        $result.Count | Should Be 7
        $script:fixture.Writes.Count | Should Be 0
        $script:fixture.Attempts.Count | Should Be 0
        @($script:fixture.Policies | Where-Object { $_.$Property -eq $Expected }).Count | Should Be 0
    }

    It "skips compliant policies and is idempotent in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.Policies[0].$Property = $Expected
        $null = Invoke-PolicyScript $File
        $script:fixture.Writes.Count | Should Be 6
        $null = Invoke-PolicyScript $File
        $script:fixture.Writes.Count | Should Be 6
    }

    It "rejects conflicting selectors before connecting in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $caught = $false
        try {
            $null = Invoke-PolicyScript $File @{ AllPolicies = $true; PolicyIdentity = @("Global") }
        }
        catch {
            $_.FullyQualifiedErrorId | Should Match "AmbiguousParameterSet"
            $caught = $true
        }
        if (-not $caught) {
            throw "Conflicting selectors were not rejected. Connections: $($script:fixture.Connections); writes: $($script:fixture.Writes.Count)."
        }
        $script:fixture.Connections | Should Be 0
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "validates every selected target before writing in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        { Invoke-PolicyScript $File @{ PolicyIdentity = @("Global", "Missing") } } | Should Throw "requested meeting policy"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "rejects an empty inventory before writing in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.Policies = @()
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "empty or incomplete"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "requires Global in the all-policy inventory in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.Policies = @($script:fixture.Policies | Where-Object Identity -ne "Global")
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "Global is required"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "rejects duplicate identities before writing in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.Policies += $script:fixture.Policies[0].PSObject.Copy()
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "missing or duplicate"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "rejects missing identities before writing in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.Policies[-1].Identity = ""
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "missing or duplicate"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "surfaces inventory errors without partial updates in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.FailEnumeration = $true
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "enumeration failed"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "stops on a rejected policy without silently skipping it in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.RejectIdentity = "Tag:LabMeetings"
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "Teams rejected update"
        $script:fixture.Attempts.Count | Should Be 2
        $script:fixture.Writes.Count | Should Be 1
        $script:fixture.Policies[0].$Property | Should Be $Expected
        $script:fixture.Policies[1].$Property | Should Not Be $Expected
    }

    It "stops with read-only policy guidance in <File> for an <ErrorSource> rejection" -TestCases $script:readOnlyCases {
        param($File, $Property, $Expected, $ErrorSource)
        $script:fixture.Policies[1].Identity = "Tag:AllOn"
        $script:fixture.RejectIdentity = "Tag:AllOn"
        $rejection = "Invalid input parameters Tenant Admin can't modify first party documents Please check your request parameters. CorrelationId: fixture-correlation"
        $message = if ($ErrorSource -eq "Exception") { $rejection } else { "Invalid input parameters." }
        $original = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new($message),
            "TeamsFirstPartyDocument",
            [System.Management.Automation.ErrorCategory]::InvalidArgument,
            "Tag:AllOn"
        )
        if ($ErrorSource -eq "ErrorDetails") {
            $original.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                (@{ message = $rejection } | ConvertTo-Json -Compress)
            )
        }
        $script:fixture.RejectError = $original
        $caught = $null
        try { $null = Invoke-PolicyScript $File } catch { $caught = $_ }
        if ($null -eq $caught) { throw "The read-only policy rejection did not stop execution." }
        $caught.FullyQualifiedErrorId | Should Match "SecureM365TeamsReadOnlyPolicy"
        $caught.TargetObject | Should Be "Tag:AllOn"
        $caught.Exception.Message | Should Match "Microsoft-managed read-only"
        $caught.Exception.Message | Should Match "-PolicyIdentity Global"
        $caught.Exception.Message | Should Match "custom policy"
        $caught.Exception.Message | Should Match "not rolled back"
        $caught.Exception.Message | Should Match "fixture-correlation"
        $caught.Exception.InnerException.Message | Should Be $original.Exception.Message
        ($script:fixture.Attempts -join ",") | Should Be "Global,Tag:AllOn"
        $script:fixture.Writes.Count | Should Be 1
        $script:fixture.Policies[0].$Property | Should Be $Expected
        @($script:fixture.Policies | Select-Object -Skip 1 | Where-Object { $_.$Property -eq $Expected }).Count | Should Be 0

        $readFailures = @{}
        $data = @{ Teams = $script:fixture.Policies }
        $assessment = Get-TeamsAssessment -Property $Property -Expected $Expected
        $assessment.Status | Should Be "NOT-CONFIGURED"
        $assessment.Details | Should Match "Tag:AllOn"
        $assessment.Details | Should Match "read-only"
    }

    It "preserves ordinary access-denied errors in <File> without misclassifying them" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.RejectIdentity = "Tag:LabMeetings"
        $original = [System.Management.Automation.ErrorRecord]::new(
            [System.UnauthorizedAccessException]::new("Forbidden: Access Denied."),
            "TeamsAccessDenied",
            [System.Management.Automation.ErrorCategory]::PermissionDenied,
            "Tag:LabMeetings"
        )
        $original.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"code":"Forbidden","message":"Request access."}')
        $script:fixture.RejectError = $original
        $caught = $null
        try { $null = Invoke-PolicyScript $File } catch { $caught = $_ }
        if ($null -eq $caught) { throw "The access-denied error did not stop execution." }
        $caught.FullyQualifiedErrorId | Should Match "TeamsAccessDenied"
        $caught.Exception.Message | Should Be $original.Exception.Message
        $caught.ErrorDetails.Message | Should Be $original.ErrorDetails.Message
        $caught.TargetObject | Should Be "Tag:LabMeetings"
        $script:fixture.Attempts.Count | Should Be 2
        $script:fixture.Writes.Count | Should Be 1
    }

    It "retains the tenant guard in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.WrongTenant = $true
        { Invoke-PolicyScript $File @{ AllPolicies = $true } } | Should Throw "instead of"
        $script:fixture.Disconnected | Should Be $true
        $script:fixture.Reads.Count | Should Be 0
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "preserves device authentication and high-impact confirmations in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $null = Invoke-PolicyScript $File @{ AllPolicies = $true; UseDeviceAuthentication = $true }
        $script:fixture.DeviceAuthentication | Should Be $true
        $binding = $script:policySources[$File].ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq "CmdletBinding" }
        ($binding.NamedArguments | Where-Object ArgumentName -eq "SupportsShouldProcess").Argument.SafeGetValue() | Should Be $true
        ($binding.NamedArguments | Where-Object ArgumentName -eq "ConfirmImpact").Argument.SafeGetValue() | Should Be "High"
    }

    It "rejects a response for a different selected policy in <File>" -TestCases $script:policyCases {
        param($File, $Property, $Expected)
        $script:fixture.WrongReadIdentity = $true
        { Invoke-PolicyScript $File @{ PolicyIdentity = @("LabMeetings") } } | Should Throw "requested meeting policy"
        $script:fixture.Attempts.Count | Should Be 0
    }

    It "keeps script 99's all-policy audit and passes it when every policy is editable and updated" {
        foreach ($case in $script:policyCases) {
            $null = Invoke-PolicyScript $case.File @{ PolicyIdentity = @("Global") }
        }
        $readFailures = @{}
        $data = @{ Teams = $script:fixture.Policies }
        foreach ($case in $script:policyCases) {
            $assessment = Get-TeamsAssessment -Property $case.Property -Expected $case.Expected
            $assessment.Status | Should Be "NOT-CONFIGURED"
            $assessment.Details | Should Match "Tag:LabMeetings"
        }
        foreach ($case in $script:policyCases) {
            $null = Invoke-PolicyScript $case.File
            $assessment = Get-TeamsAssessment -Property $case.Property -Expected $case.Expected
            $assessment.Status | Should Be "IMPLEMENTED"
        }
    }
}
