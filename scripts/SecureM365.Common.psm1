function Connect-SecureM365Graph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $TenantId,

        [string[]] $AdditionalScopes = @(),
        [switch] $UseDeviceCode
    )

    $readScopes = @(
        "AuditLog.Read.All"
        "Policy.Read.All"
        "RoleManagement.Read.Directory"
        "SecurityEvents.Read.All"
        "User.Read.All"
    )
    $scopes = @(
        $readScopes
        $AdditionalScopes
    ) | Sort-Object -Unique

    $connectParameters = @{
        TenantId     = $TenantId.Guid
        Scopes       = [string[]] $scopes
        ContextScope = "Process"
        NoWelcome    = $true
        ErrorAction  = "Stop"
    }
    if ($UseDeviceCode) {
        $connectParameters.UseDeviceCode = $true
    }

    Connect-MgGraph @connectParameters
    $context = Get-MgContext

    if (
        $null -eq $context -or
        $context.TenantId -ne $TenantId.Guid -or
        $context.AuthType -ne "Delegated"
    ) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "Microsoft Graph did not connect to tenant '$($TenantId.Guid)' with delegated authentication."
    }

    $missingScopes = @(
        $scopes |
        Where-Object { $_ -notin $context.Scopes }
    )
    if ($missingScopes.Count -gt 0) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        throw "The Graph token is missing consented scopes: $($missingScopes -join ', ')"
    }

    $context
}

function Connect-SecureM365Teams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $TenantId,

        [switch] $UseDeviceAuthentication,
        [switch] $ValidateMeetingPolicyAccess
    )

    $connectParameters = @{
        TenantId    = $TenantId.Guid
        ErrorAction = "Stop"
    }
    if ($UseDeviceAuthentication) {
        $connectParameters.UseDeviceAuthentication = $true
    }

    $connection = Connect-MicrosoftTeams @connectParameters
    if ([string] $connection.TenantId -ne $TenantId.Guid) {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        throw "Microsoft Teams connected to tenant '$($connection.TenantId)' instead of '$($TenantId.Guid)'."
    }

    if ($ValidateMeetingPolicyAccess) {
        try {
            $globalPolicy = @(Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop)
            if ($globalPolicy.Count -ne 1 -or $globalPolicy[0].Identity -ne "Global") {
                throw "Microsoft Teams did not return the Global meeting policy."
            }
        }
        catch {
            $details = $_.Exception.Message
            if (-not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
                $details += " $($_.ErrorDetails.Message)"
            }
            throw [System.InvalidOperationException]::new(
                "Microsoft Teams connected to tenant '$($TenantId.Guid)', but reading the Global meeting policy failed. " +
                "For Forbidden/Access Denied, verify the Teams account has an active role permitted to read meeting policies " +
                "(for example, Teams Communications Administrator). Activate PIM if needed and allow role changes to propagate, " +
                "then run Disconnect-MicrosoftTeams and rerun script 01 with -IncludeTeams. Graph consent does not grant Teams permissions. " +
                "Original error: $details",
                $_.Exception
            )
        }
    }

    $connection
}

function Get-SecureM365TeamsMeetingPolicy {
    [CmdletBinding(DefaultParameterSetName = "SelectedPolicies")]
    param(
        [Parameter(ParameterSetName = "SelectedPolicies")]
        [ValidateNotNullOrEmpty()]
        [string[]] $PolicyIdentity = @("Global"),

        [Parameter(Mandatory, ParameterSetName = "AllPolicies")]
        [switch] $AllPolicies
    )

    $policies = @(
        if ($AllPolicies) {
            Get-CsTeamsMeetingPolicy -ErrorAction Stop
        }
        else {
            foreach ($identity in $PolicyIdentity) {
                if ([string]::IsNullOrWhiteSpace($identity)) {
                    throw "Supply a nonempty Teams meeting policy identity."
                }
                $matches = @(Get-CsTeamsMeetingPolicy -Identity $identity -ErrorAction Stop)
                $expectedIdentity = if ($identity -eq "Global") {
                    "Global"
                }
                else {
                    "Tag:" + ($identity -replace '^Tag:', '')
                }
                if ($matches.Count -ne 1 -or [string] $matches[0].Identity -ne $expectedIdentity) {
                    throw "Teams did not return exactly the requested meeting policy '$identity'. No policies were changed."
                }
                $matches[0]
            }
        }
    )

    $seen = @{}
    foreach ($policy in $policies) {
        $identity = [string] $policy.Identity
        if ([string]::IsNullOrWhiteSpace($identity) -or $seen.ContainsKey($identity)) {
            throw "Teams returned a missing or duplicate meeting policy identity. No policies were changed."
        }
        $seen[$identity] = $true
    }
    if ($policies.Count -eq 0 -or ($AllPolicies -and -not $seen.ContainsKey("Global"))) {
        throw "Teams returned an empty or incomplete meeting policy inventory (Global is required for -AllPolicies). No policies were changed."
    }

    $policies
}

function Get-SecureM365TeamsMeetingPolicyUpdateError {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)]
        [string] $PolicyIdentity,

        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $details = $ErrorRecord.Exception.Message
    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $details += " $($ErrorRecord.ErrorDetails.Message)"
    }
    # Ordinary authorization and validation failures must retain their original errors.
    if ($details -notmatch "Tenant Admin can't modify first party documents") {
        return $ErrorRecord
    }

    $message = "Teams policy '$PolicyIdentity' is a Microsoft-managed read-only preset. " +
        "It cannot be edited by a tenant administrator; adding roles will not fix this error. " +
        "Use -PolicyIdentity Global or explicitly select a tenant-created custom policy. " +
        "Review user/group assignments before replacing a preset with a compliant policy. " +
        "Execution stopped at this policy; remaining policies were not processed and earlier updates were not rolled back. " +
        "Script 99 still audits read-only and unused presets. Original Teams error: $details"
    [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($message, $ErrorRecord.Exception),
        "SecureM365TeamsReadOnlyPolicy",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $PolicyIdentity
    )
}

function Get-SecureM365GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        [hashtable] $Headers = @{}
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    while ($nextLink) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -Headers $Headers -ErrorAction Stop
        if ($null -eq $page.value) {
            throw "Microsoft Graph returned no collection value for '$nextLink'."
        }
        foreach ($item in @($page.value)) {
            [void] $items.Add($item)
        }
        $nextLink = $page.'@odata.nextLink'
    }

    $items.ToArray()
}

function Get-SecureM365EnabledConditionalAccessPolicy {
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999' |
        Where-Object { $_.state -eq "enabled" }
}

function New-SecureM365ConditionalAccessPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $BodyParameter
    )

    $existingPolicies = @(
        Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
        Where-Object { $_.DisplayName -eq $BodyParameter.displayName }
    )
    if ($existingPolicies.Count -gt 0) {
        $existingIds = $existingPolicies.Id -join ", "
        throw "A policy named '$($BodyParameter.displayName)' already exists ($existingIds). Review it instead of creating a duplicate."
    }

    New-MgIdentityConditionalAccessPolicy `
        -BodyParameter $BodyParameter `
        -ErrorAction Stop
}

function Test-SecureM365CaTargetsAllUsers {
    param([Parameter(Mandatory)] $Policy)
    @($Policy.conditions.users.includeUsers) -contains "All"
}

function Test-SecureM365CaHasOnlyApprovedExclusions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Policy,

        [string[]] $ApprovedExcludedUserIds = @(),
        [string[]] $ApprovedExcludedGroupIds = @(),
        [string[]] $ApprovedExcludedRoleIds = @(),
        [switch] $AllowGuestOrExternalUserExclusion
    )

    $users = $Policy.conditions.users
    $unexpectedUsers = @(
        @($users.excludeUsers) |
        Where-Object { $_ -and $_ -notin $ApprovedExcludedUserIds }
    )
    $unexpectedGroups = @(
        @($users.excludeGroups) |
        Where-Object { $_ -and $_ -notin $ApprovedExcludedGroupIds }
    )
    $unexpectedRoles = @(
        @($users.excludeRoles) |
        Where-Object { $_ -and $_ -notin $ApprovedExcludedRoleIds }
    )
    $hasGuestExclusion =
        $null -ne $users.excludeGuestsOrExternalUsers -and
        -not $AllowGuestOrExternalUserExclusion

    ($unexpectedUsers.Count -eq 0) -and
    ($unexpectedGroups.Count -eq 0) -and
    ($unexpectedRoles.Count -eq 0) -and
    (-not $hasGuestExclusion)
}

function Test-SecureM365CaTargetsAllResources {
    param([Parameter(Mandatory)] $Policy)

    (@($Policy.conditions.applications.includeApplications) -contains "All") -and
    (@($Policy.conditions.applications.excludeApplications).Count -eq 0)
}

function Test-SecureM365CaRequiresMfa {
    param([Parameter(Mandatory)] $Policy)

    $builtInControls = @($Policy.grantControls.builtInControls)
    $strength = $Policy.grantControls.authenticationStrength

    ($builtInControls -contains "mfa") -or
    ($strength.id -eq "00000000-0000-0000-0000-000000000002") -or
    ($strength.requirementsSatisfied -eq "mfa")
}

function Test-SecureM365CaUsesEveryTimeSignInFrequency {
    param([Parameter(Mandatory)] $Policy)

    $frequency = $Policy.sessionControls.signInFrequency
    ($null -ne $frequency) -and
    ($frequency.isEnabled -eq $true) -and
    ($frequency.frequencyInterval -eq "everyTime")
}

function Get-SecureM365SecurityDefaultsEnabled {
    $policy = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
        -ErrorAction Stop
    $policy.isEnabled -eq $true
}

function Reset-SecureM365ScoreCache {
    $script:SecureScoreProfiles = $null
    $script:LatestSecureScore = $null
}

function Test-SecureM365ScoreAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [string] $ControlName
    )

    if ($null -eq $script:SecureScoreProfiles) {
        $script:SecureScoreProfiles = @(
            Get-SecureM365GraphCollection `
                -Uri 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=999'
        )
    }

    if ($null -eq $script:LatestSecureScore) {
        $page = Invoke-MgGraphRequest `
            -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=30' `
            -ErrorAction Stop
        $script:LatestSecureScore = @(
            $page.value |
            Where-Object { $_.vendorInformation.vendor -eq "Microsoft" }
        ) |
            Sort-Object { [datetimeoffset] $_.createdDateTime } -Descending |
            Select-Object -First 1
    }

    if ($null -eq $script:LatestSecureScore) {
        throw "Microsoft Graph returned no Microsoft Secure Score snapshots."
    }

    $profile = @(
        $script:SecureScoreProfiles |
        Where-Object {
            $_.id -eq $ControlName -and
            $_.vendorInformation.vendor -eq "Microsoft"
        }
    ) | Select-Object -First 1

    if ($null -eq $profile) {
        $profile = @(
            $script:SecureScoreProfiles |
            Where-Object {
                $_.title -eq $Title -and
                $_.vendorInformation.vendor -eq "Microsoft"
            }
        ) | Select-Object -First 1
    }

    if ($null -eq $profile) {
        return [pscustomobject]@{
            Action   = $Title
            Resolved = $false
            Details  = "The Microsoft Secure Score control profile was not found."
        }
    }

    $control = @(
        $script:LatestSecureScore.controlScores |
        Where-Object { $_.controlName -eq $profile.id }
    ) | Select-Object -First 1

    $currentScore = if ($null -eq $control) { 0.0 } else { [double] $control.score }
    $maxScore = [double] $profile.maxScore
    $controlFound = $null -ne $control

    [pscustomobject]@{
        Action          = $Title
        ControlName     = $profile.id
        ControlFound    = $controlFound
        CurrentScore    = $currentScore
        MaximumScore    = $maxScore
        Resolved        = $controlFound -and ($currentScore -ge $maxScore)
        ScoreSnapshotAt = $script:LatestSecureScore.createdDateTime
        Details         = if ($controlFound) {
            $null
        }
        else {
            "The control is not present in the latest Secure Score snapshot."
        }
    }
}

Export-ModuleMember -Function @(
    "Connect-SecureM365Graph"
    "Connect-SecureM365Teams"
    "Get-SecureM365TeamsMeetingPolicy"
    "Get-SecureM365TeamsMeetingPolicyUpdateError"
    "Get-SecureM365GraphCollection"
    "Get-SecureM365EnabledConditionalAccessPolicy"
    "New-SecureM365ConditionalAccessPolicy"
    "Test-SecureM365CaTargetsAllUsers"
    "Test-SecureM365CaHasOnlyApprovedExclusions"
    "Test-SecureM365CaTargetsAllResources"
    "Test-SecureM365CaRequiresMfa"
    "Test-SecureM365CaUsesEveryTimeSignInFrequency"
    "Get-SecureM365SecurityDefaultsEnabled"
    "Reset-SecureM365ScoreCache"
    "Test-SecureM365ScoreAction"
)
