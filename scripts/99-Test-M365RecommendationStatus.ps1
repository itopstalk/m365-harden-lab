#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, MicrosoftTeams

<#
.SYNOPSIS
Displays the live status of the 11 Microsoft 365 recommendations in the guide.

.DESCRIPTION
Run after scripts 00 and 01. Uses read-only Microsoft Graph v1.0 and Teams queries,
not Secure Score snapshots. Prints green IMPLEMENTED, yellow NOT-CONFIGURED, or
cyan UNKNOWN, followed by evidence or the reason a check could not be completed.
Report-only and disabled Conditional Access policies do not count as enforced.
Complex combinations of narrower policies may need manual review.

MFA and SSPR checks also use the authentication-method registration report, which
requires Entra ID P1/P2 and can lag changes by up to 36 hours. Missing permissions,
data, or manual evidence are UNKNOWN, never evidence of missing configuration.
Teams checks include Global and every custom meeting policy, even unused policies.

.PARAMETER TenantId
Target tenant in the worldwide cloud. If omitted, uses the delegated Graph tenant
connected by script 01 in this PowerShell process. Each service connection is
checked against that tenant before its configuration is read.

.PARAMETER ApprovedExcludedUserId
Explicitly approved Conditional Access user exclusions, such as the object IDs
returned by script 04. Does not exempt these users from MFA registration checks.

.PARAMETER ApprovedExcludedGroupId
Explicitly approved Conditional Access group exclusions.

.PARAMETER ApprovedExcludedRoleId
Explicitly approved Conditional Access exclusions, using role template IDs.

.PARAMETER ApprovedBaselinePath
Optional reviewed role-assignment CSV with PrincipalId, RoleName, and
DirectoryScopeId columns, as exported by script 50 and used by script 52.
Review and approve it first; an unreviewed export is not least-privilege evidence.
Without a baseline the least-privilege recommendation is UNKNOWN.

.PARAMETER SsprAllScopeConfirmed
Use only after confirming Entra ID > Password reset > Properties is set to All
in this tenant. Graph exposes per-user SSPR state, not that exact tenant setting.
The SSPR check also requires every enabled member to be reported SSPR-enabled.

.PARAMETER UseGraphDeviceCode
Use device-code authentication for Microsoft Graph.

.PARAMETER UseTeamsDeviceAuthentication
Use device authentication for Microsoft Teams.

.PARAMETER PassThru
Also return the 11 structured result objects for filtering or export.

.EXAMPLE
.\99-Test-M365RecommendationStatus.ps1

.EXAMPLE
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

.EXAMPLE
$results = .\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -PassThru
#>

[CmdletBinding()]
param(
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,

    [guid[]] $ApprovedExcludedUserId = @(),
    [guid[]] $ApprovedExcludedGroupId = @(),
    [guid[]] $ApprovedExcludedRoleId = @(),
    [string] $ApprovedBaselinePath,
    [switch] $SsprAllScopeConfirmed,
    [Alias("UseDeviceCode")]
    [switch] $UseGraphDeviceCode,
    [switch] $UseTeamsDeviceAuthentication,
    [switch] $PassThru
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

if (-not $PSBoundParameters.ContainsKey("TenantId")) {
    $existingContext = Get-MgContext
    $connectedTenantId = [guid]::Empty
    if (
        $null -eq $existingContext -or
        $existingContext.AuthType -ne "Delegated" -or
        -not [guid]::TryParse([string] $existingContext.TenantId, [ref] $connectedTenantId) -or
        $connectedTenantId -eq [guid]::Empty
    ) {
        throw "Run script 01 in this PowerShell process, or supply -TenantId with the intended tenant GUID."
    }
    $TenantId = $connectedTenantId
}

$context = Connect-SecureM365Graph -TenantId $TenantId -UseDeviceCode:$UseGraphDeviceCode
if ($context.Environment -ne "Global") {
    throw "This script supports the Microsoft 365 worldwide cloud only."
}

$approvedExclusions = @{
    ApprovedExcludedUserIds  = @($ApprovedExcludedUserId | ForEach-Object { $_.Guid })
    ApprovedExcludedGroupIds = @($ApprovedExcludedGroupId | ForEach-Object { $_.Guid })
    ApprovedExcludedRoleIds  = @($ApprovedExcludedRoleId | ForEach-Object { $_.Guid })
}

function New-Assessment {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("IMPLEMENTED", "NOT-CONFIGURED", "UNKNOWN")]
        [string] $Status,

        [Parameter(Mandatory)]
        [string] $Details
    )
    [pscustomobject]@{ Status = $Status; Details = $Details }
}

function Get-CheckData {
    param([Parameter(Mandatory)] [string] $Name)
    if ($readFailures.ContainsKey($Name)) {
        throw "Cannot read ${Name}: $($readFailures[$Name])"
    }
    $data[$Name]
}

function Get-CheckedSecurityDefaults {
    $policy = Get-CheckData "SecurityDefaults"
    if ($policy.isEnabled -isnot [bool]) {
        throw "The security defaults response did not contain a Boolean isEnabled value."
    }
    $policy.isEnabled
}

function Test-ReportMfaGrant {
    param([Parameter(Mandatory)] $Policy)

    $grant = $Policy.grantControls
    $controls = @($grant.builtInControls | Where-Object { $_ })
    $strength = $grant.authenticationStrength
    $hasMfaStrength =
        $strength.requirementsSatisfied -eq "mfa" -or
        $strength.id -in @(
            "00000000-0000-0000-0000-000000000002"
            "00000000-0000-0000-0000-000000000003"
            "00000000-0000-0000-0000-000000000004"
        )
    if (
        $controls -contains "block" -or
        (-not $hasMfaStrength -and $controls -notcontains "mfa")
    ) {
        return $false
    }
    if ($grant.operator -eq "AND") {
        return $true
    }
    if ($grant.operator -ne "OR") {
        return $false
    }

    # An OR alternative such as a compliant device lets the user bypass MFA.
    $alternatives = @($controls | Where-Object { $_ -ne "mfa" })
    $alternatives.Count -eq 0 -and
        @($grant.termsOfUse | Where-Object { $_ }).Count -eq 0 -and
        @($grant.customAuthenticationFactors | Where-Object { $_ }).Count -eq 0 -and
        ($null -eq $strength -or $hasMfaStrength)
}

function Test-ReportPolicyScope {
    param(
        [Parameter(Mandatory)] $Policy,
        [ValidateSet("None", "SignIn", "User")] [string] $Risk = "None",
        [switch] $Legacy
    )

    if (
        $Policy.state -ne "enabled" -or
        -not (Test-SecureM365CaHasOnlyApprovedExclusions -Policy $Policy @approvedExclusions) -or
        -not (Test-SecureM365CaTargetsAllResources $Policy)
    ) {
        return $false
    }

    $conditions = $Policy.conditions
    $apps = $conditions.applications
    if (
        $null -ne $apps.applicationFilter -or
        @($apps.includeUserActions | Where-Object { $_ }).Count -gt 0 -or
        @($apps.includeAuthenticationContextClassReferences | Where-Object { $_ }).Count -gt 0
    ) {
        return $false
    }

    $clients = @($conditions.clientAppTypes)
    if ($clients -notcontains "all") {
        if (
            -not $Legacy -or
            $clients -notcontains "exchangeActiveSync" -or
            $clients -notcontains "other"
        ) {
            return $false
        }
    }

    $allowedConditions = @("users", "applications", "clientAppTypes", "@odata.type")
    if ($Risk -eq "SignIn") { $allowedConditions += "signInRiskLevels" }
    if ($Risk -eq "User") { $allowedConditions += "userRiskLevels" }
    $conditionNames = if ($conditions -is [System.Collections.IDictionary]) {
        @($conditions.Keys)
    }
    else {
        @($conditions.PSObject.Properties.Name)
    }
    foreach ($name in $conditionNames) {
        if ($name -in $allowedConditions) { continue }
        $value = $conditions.$name
        if ($null -eq $value -or @($value).Count -eq 0) { continue }
        if (
            $name -eq "platforms" -and
            @($value.includePlatforms) -contains "all" -and
            @($value.excludePlatforms | Where-Object { $_ }).Count -eq 0
        ) { continue }
        if (
            $name -eq "locations" -and
            @($value.includeLocations) -contains "All" -and
            @($value.excludeLocations | Where-Object { $_ }).Count -eq 0
        ) { continue }
        return $false
    }
    $true
}

function Get-RegistrationCoverage {
    param([switch] $Administrators)

    $users = @(Get-CheckData "Users")
    if ($users.Count -eq 0) { throw "No users were returned; an empty tenant inventory cannot verify coverage." }
    $registration = @(Get-CheckData "Registration")
    $byId = @{}
    foreach ($row in $registration) {
        if ([string]::IsNullOrWhiteSpace($row.id) -or $byId.ContainsKey($row.id)) {
            throw "The registration report contains a missing or duplicate user ID."
        }
        $byId[$row.id] = $row
    }

    $directAdminIds = @()
    if ($Administrators) {
        $directAdminIds = @((Get-CheckData "RoleAssignments").principalId)
        $unresolvedPrincipals = @($directAdminIds | Where-Object { $_ -notin @($users.id) })
        if ($unresolvedPrincipals.Count -gt 0) {
            throw "Active role assignments include $($unresolvedPrincipals.Count) principals not found in the user inventory. Group-based administrator membership or other principal types need manual review; the registration report alone cannot prove current membership."
        }
    }
    $selectedUsers = @(
        foreach ($user in $users) {
            if (
                [string]::IsNullOrWhiteSpace($user.id) -or
                $user.accountEnabled -isnot [bool] -or
                $user.userType -notin @("Member", "Guest")
            ) {
                throw "The user inventory is missing required identity, accountEnabled, or userType data."
            }
            if (-not $user.accountEnabled) { continue }
            $row = $byId[$user.id]
            if ($Administrators) {
                if ($user.id -notin $directAdminIds -and $row.isAdmin -ne $true) { continue }
            }
            elseif ($user.userType -ne "Member") {
                continue
            }
            [pscustomobject]@{ User = $user; Registration = $row }
        }
    )
    if ($selectedUsers.Count -eq 0) {
        throw "No enabled users were identified for this registration check; coverage cannot be verified."
    }
    $selectedUsers
}

function Get-MfaAssessment {
    param([switch] $Administrators)

    $securityDefaults = Get-CheckedSecurityDefaults
    $protection = $securityDefaults
    $policyEvidence = "Security defaults is enabled."
    if (-not $securityDefaults) {
        $policies = @(Get-CheckData "ConditionalAccess")
        $mfaPolicies = @(
            $policies | Where-Object {
                (Test-ReportPolicyScope $_) -and (Test-ReportMfaGrant $_)
            }
        )
        $allUserPolicies = @($mfaPolicies | Where-Object { Test-SecureM365CaTargetsAllUsers $_ })
        $protection = $allUserPolicies.Count -gt 0
        $policyEvidence = "Enforced policy: $($allUserPolicies.displayName -join ', ')."
        if ($Administrators -and -not $protection) {
            $roles = @(Get-CheckData "RoleDefinitions")
            $assignments = @(Get-CheckData "RoleAssignments")
            if ($assignments.Count -eq 0) { throw "No active role assignments were returned." }
            $requiredRoleIds = @(
                foreach ($assignment in $assignments) {
                    $role = @($roles | Where-Object { $_.id -eq $assignment.roleDefinitionId })
                    if (
                        $role.Count -ne 1 -or
                        $role[0].isBuiltIn -ne $true -or
                        [string]::IsNullOrWhiteSpace($role[0].templateId)
                    ) {
                        throw "An assigned role could not be resolved to a built-in template. Verify administrator MFA coverage manually."
                    }
                    $role[0].templateId
                }
            ) | Sort-Object -Unique
            $coveredRoleIds = @(
                foreach ($policy in $mfaPolicies) {
                    @($policy.conditions.users.includeRoles) |
                        Where-Object { $_ -notin @($policy.conditions.users.excludeRoles) }
                }
            )
            $missingRoles = @($requiredRoleIds | Where-Object { $_ -notin $coveredRoleIds })
            $protection = $requiredRoleIds.Count -gt 0 -and $missingRoles.Count -eq 0
            $policyEvidence = "Enforced MFA policies cover all $($requiredRoleIds.Count) currently assigned role templates."
        }
        if (-not $protection) {
            $narrowMfaPolicies = @(
                $policies | Where-Object {
                    $_.state -eq "enabled" -and (Test-ReportMfaGrant $_)
                }
            )
            if ($narrowMfaPolicies.Count -gt 0) {
                return New-Assessment "UNKNOWN" "MFA policies exist, but broad coverage with only approved exclusions was not verified. Review scopes, exclusions, and combinations of narrower policies."
            }
            return New-Assessment "NOT-CONFIGURED" "Security defaults is disabled and no enabled policy unconditionally requires MFA. Report-only policies and MFA OR a non-MFA grant do not count."
        }
    }

    $coverage = @(Get-RegistrationCoverage -Administrators:$Administrators)
    $missing = @($coverage | Where-Object { $_.Registration.isMfaCapable -isnot [bool] })
    $notCapable = @($coverage | Where-Object { $_.Registration.isMfaCapable -eq $false })
    if ($notCapable.Count -gt 0) {
        return New-Assessment "NOT-CONFIGURED" "$policyEvidence $($notCapable.Count) of $($coverage.Count) enabled accounts are not reported MFA-capable; $($missing.Count) have missing data."
    }
    if ($missing.Count -gt 0) {
        return New-Assessment "UNKNOWN" "$policyEvidence MFA capability data is missing for $($missing.Count) of $($coverage.Count) enabled accounts."
    }
    New-Assessment "IMPLEMENTED" "$policyEvidence All $($coverage.Count) checked enabled accounts are reported MFA-capable, including any emergency accounts."
}

function Get-RiskAssessment {
    param([ValidateSet("SignIn", "User")] [string] $Risk)

    if (Get-CheckedSecurityDefaults) {
        return New-Assessment "NOT-CONFIGURED" "Security defaults is enabled instead of risk-based Conditional Access. This is an alternative mitigation, not an implemented risk policy."
    }
    $policies = @(Get-CheckData "ConditionalAccess")
    $matching = @(
        $policies | Where-Object {
            $policy = $_
            $riskMatches = if ($Risk -eq "SignIn") {
                @($policy.conditions.signInRiskLevels) -contains "medium" -and
                    @($policy.conditions.signInRiskLevels) -contains "high"
            }
            else {
                $controls = @($policy.grantControls.builtInControls)
                $remediations = @($controls | Where-Object { $_ -in @("passwordChange", "riskRemediation") })
                @($policy.conditions.userRiskLevels) -contains "high" -and
                    $policy.grantControls.operator -eq "AND" -and
                    $remediations.Count -eq 1 -and
                    ($controls -notcontains "riskRemediation" -or $null -ne $policy.grantControls.authenticationStrength)
            }
            (Test-ReportPolicyScope -Policy $policy -Risk $Risk) -and
                (Test-SecureM365CaTargetsAllUsers $policy) -and
                (Test-ReportMfaGrant $policy) -and
                (Test-SecureM365CaUsesEveryTimeSignInFrequency $policy) -and
                $policy.sessionControls.signInFrequency.authenticationType -eq "primaryAndSecondaryAuthentication" -and
                $riskMatches
        }
    )
    if ($matching.Count -gt 0) {
        return New-Assessment "IMPLEMENTED" "Enforced risk policy with MFA and every-time reauthentication: $($matching.displayName -join ', ')."
    }
    $riskProperty = if ($Risk -eq "SignIn") { "signInRiskLevels" } else { "userRiskLevels" }
    $enabledRiskPolicies = @(
        $policies | Where-Object {
            $_.state -eq "enabled" -and @($_.conditions.$riskProperty | Where-Object { $_ }).Count -gt 0
        }
    )
    if ($enabledRiskPolicies.Count -gt 0) {
        return New-Assessment "UNKNOWN" "Enabled risk policies exist, but the guide's all-user/all-resource baseline, approved exclusions, risk levels, MFA/remediation, and every-time reauthentication were not all verified."
    }
    New-Assessment "NOT-CONFIGURED" "No enabled $Risk risk policy was found. Disabled and report-only policies do not count."
}

function Get-TeamsAssessment {
    param([string] $Property, $Expected)

    $policies = @(Get-CheckData "Teams")
    if ($policies.Count -eq 0 -or @($policies | Where-Object Identity -eq "Global").Count -ne 1) {
        throw "Teams did not return the Global meeting policy; an empty or incomplete policy inventory cannot pass."
    }
    $unreadable = @($policies | Where-Object { $null -eq $_.$Property })
    if ($unreadable.Count -gt 0) {
        throw "Teams did not return '$Property' on every meeting policy."
    }
    if ($Expected -is [bool] -and @($policies | Where-Object { $_.$Property -isnot [bool] }).Count -gt 0) {
        throw "Teams returned a non-Boolean '$Property' value."
    }
    $nonCompliant = @($policies | Where-Object { $_.$Property -ne $Expected })
    if ($nonCompliant.Count -gt 0) {
        return New-Assessment "NOT-CONFIGURED" "$Property must be '$Expected'. Policies needing changes: $($nonCompliant.Identity -join ', ')."
    }
    New-Assessment "IMPLEMENTED" "$Property is '$Expected' on all $($policies.Count) meeting policies (Global and every custom policy)."
}

function Get-RoleBaselineAssessment {
    $assignments = @(Get-CheckData "RoleAssignments")
    $roles = @(Get-CheckData "RoleDefinitions")
    if ($assignments.Count -eq 0) { throw "No active role assignments were returned." }
    if ([string]::IsNullOrWhiteSpace($ApprovedBaselinePath)) {
        return New-Assessment "UNKNOWN" "$($assignments.Count) active role assignments found. Supply -ApprovedBaselinePath with a reviewed CSV; software cannot infer each administrator's legitimate tasks."
    }
    $baseline = @(Import-Csv -LiteralPath $ApprovedBaselinePath -ErrorAction Stop)
    if ($baseline.Count -eq 0) { throw "The approved role baseline is empty." }
    foreach ($row in $baseline) {
        $principalId = [guid]::Empty
        if (
            -not [guid]::TryParse([string] $row.PrincipalId, [ref] $principalId) -or
            $principalId -eq [guid]::Empty -or
            [string]::IsNullOrWhiteSpace($row.RoleName) -or
            $row.DirectoryScopeId -notlike "/*"
        ) {
            throw "Every baseline row must contain a valid PrincipalId, RoleName, and DirectoryScopeId."
        }
    }
    $unexpected = @(
        foreach ($assignment in $assignments) {
            $role = @($roles | Where-Object { $_.id -eq $assignment.roleDefinitionId })
            if ($role.Count -ne 1 -or [string]::IsNullOrWhiteSpace($role[0].displayName)) {
                throw "Cannot resolve role definition '$($assignment.roleDefinitionId)' for an active assignment."
            }
            if ([string]::IsNullOrWhiteSpace($assignment.directoryScopeId) -or $assignment.appScopeId) {
                throw "An active role assignment has an unsupported or missing directory scope; review it manually."
            }
            $approved = @(
                $baseline | Where-Object {
                    $_.PrincipalId -eq $assignment.principalId -and
                    $_.RoleName -eq $role[0].displayName -and
                    $_.DirectoryScopeId -eq $assignment.directoryScopeId
                }
            )
            if ($approved.Count -eq 0) { $assignment }
        }
    )
    if ($unexpected.Count -gt 0) {
        return New-Assessment "NOT-CONFIGURED" "$($unexpected.Count) active role assignments are outside the approved baseline. Use script 52 for the detailed comparison."
    }
    New-Assessment "IMPLEMENTED" "All $($assignments.Count) active role assignments match the reviewed baseline. Eligible PIM assignments and the baseline's business justification still need periodic review."
}

function Get-SsprAssessment {
    $coverage = @(Get-RegistrationCoverage)
    $missing = @($coverage | Where-Object { $_.Registration.isSsprEnabled -isnot [bool] })
    $notEnabled = @($coverage | Where-Object { $_.Registration.isSsprEnabled -eq $false })
    if ($notEnabled.Count -gt 0) {
        return New-Assessment "NOT-CONFIGURED" "$($notEnabled.Count) of $($coverage.Count) enabled member accounts are not reported SSPR-enabled; $($missing.Count) have missing data."
    }
    if ($missing.Count -gt 0) {
        return New-Assessment "UNKNOWN" "SSPR data is missing for $($missing.Count) of $($coverage.Count) enabled member accounts."
    }
    if (-not $SsprAllScopeConfirmed) {
        return New-Assessment "UNKNOWN" "All $($coverage.Count) enabled members are reported SSPR-enabled, but Selected groups can produce the same result. Confirm Password reset > Properties is All, then use -SsprAllScopeConfirmed."
    }
    New-Assessment "IMPLEMENTED" "All scope confirmed by the operator, and all $($coverage.Count) enabled member accounts are reported SSPR-enabled. This checks enablement, not registration completeness."
}

$readers = [ordered]@{
    SecurityDefaults = {
        Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -ErrorAction Stop
    }
    ConditionalAccess = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
            -Headers @{ Prefer = "include-unknown-enum-members" }
    }
    Users = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled,userType&$top=999'
    }
    Registration = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    }
    RoleDefinitions = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn&$top=999'
    }
    RoleAssignments = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId,appScopeId&$top=999'
    }
    Authorization = {
        Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -ErrorAction Stop
    }
    Teams = {
        Connect-SecureM365Teams -TenantId $TenantId -UseDeviceAuthentication:$UseTeamsDeviceAuthentication | Out-Null
        Get-CsTeamsMeetingPolicy -ErrorAction Stop
    }
}
$data = @{}
$readFailures = @{}
foreach ($name in $readers.Keys) {
    try {
        $data[$name] = @(& $readers[$name])
    }
    catch {
        $readFailures[$name] = $_.Exception.Message
        Write-Warning "Could not read ${name}: $($_.Exception.Message). Dependent checks will report UNKNOWN unless other evidence is sufficient."
    }
}

$checks = @(
    @{
        Title = "Ensure multifactor authentication is enabled for all users in administrative roles"
        Evaluate = { Get-MfaAssessment -Administrators }
    }
    @{
        Title = "Ensure multifactor authentication is enabled for all users"
        Evaluate = { Get-MfaAssessment }
    }
    @{
        Title = "Enable Conditional Access policies to block legacy authentication"
        Evaluate = {
            if (Get-CheckedSecurityDefaults) {
                return New-Assessment "IMPLEMENTED" "Security defaults is enabled and blocks legacy authentication."
            }
            $policies = @(Get-CheckData "ConditionalAccess")
            $blocking = @(
                $policies | Where-Object {
                    (Test-ReportPolicyScope -Policy $_ -Legacy) -and
                    (Test-SecureM365CaTargetsAllUsers $_) -and
                    @($_.grantControls.builtInControls) -contains "block"
                }
            )
            if ($blocking.Count -gt 0) {
                return New-Assessment "IMPLEMENTED" "Enforced legacy-authentication block: $($blocking.displayName -join ', ')."
            }
            $narrowBlocks = @($policies | Where-Object {
                $_.state -eq "enabled" -and @($_.grantControls.builtInControls) -contains "block"
            })
            if ($narrowBlocks.Count -gt 0) {
                return New-Assessment "UNKNOWN" "Block policies exist, but coverage of both legacy client types, all users/resources, and only approved exclusions was not verified."
            }
            New-Assessment "NOT-CONFIGURED" "Security defaults is disabled and no enabled Conditional Access block policy was found."
        }
    }
    @{
        Title = "Enable Microsoft Entra ID Identity Protection sign-in risk policies"
        Evaluate = { Get-RiskAssessment -Risk SignIn }
    }
    @{
        Title = "Enable Microsoft Entra ID Identity Protection user risk policies"
        Evaluate = { Get-RiskAssessment -Risk User }
    }
    @{
        Title = "Ensure user consent to apps accessing company data on their behalf is not allowed"
        Evaluate = {
            $policy = Get-CheckData "Authorization"
            $assigned = $policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
            if ($null -eq $assigned) { throw "The authorization policy did not return permissionGrantPoliciesAssigned." }
            $selfConsent = @($assigned | Where-Object {
                $_ -match '(?i)^managePermissionGrantsForSelf\.' -or $_ -match '(?i)(^|\.)user-default'
            })
            if ($selfConsent.Count -gt 0) {
                return New-Assessment "NOT-CONFIGURED" "User consent is permitted by: $($selfConsent -join ', ')."
            }
            New-Assessment "IMPLEMENTED" "No default-user self-consent policy is assigned. Existing consent grants are not revoked by this setting."
        }
    }
    @{
        Title = "Only invited users should be automatically admitted to Teams meetings"
        Evaluate = { Get-TeamsAssessment -Property AutoAdmittedUsers -Expected "InvitedUsers" }
    }
    @{
        Title = "Configure which users are allowed to present in Teams meetings"
        Evaluate = { Get-TeamsAssessment -Property DesignatedPresenterRoleMode -Expected "OrganizerOnlyUserOverride" }
    }
    @{
        Title = "Restrict anonymous users from joining meetings"
        Evaluate = { Get-TeamsAssessment -Property AllowAnonymousUsersToJoinMeeting -Expected $false }
    }
    @{
        Title = "Use least privileged administrative roles"
        Evaluate = { Get-RoleBaselineAssessment }
    }
    @{
        Title = "Ensure 'Self service password reset enabled' is set to 'All'"
        Evaluate = { Get-SsprAssessment }
    }
)

$checkedAt = [datetimeoffset]::UtcNow
Write-Host "`nMicrosoft 365 live recommendation status"
Write-Host "Tenant: $($TenantId.Guid) | Checked at: $($checkedAt.ToString('u'))"
Write-Host "Registration data can lag by up to 36 hours. UNKNOWN means not verified, not necessarily unconfigured.`n"

$results = @(
    for ($index = 0; $index -lt $checks.Count; $index++) {
        $check = $checks[$index]
        try {
            $assessment = & $check.Evaluate
        }
        catch {
            Write-Warning "Check $($index + 1) failed: $($_.Exception.Message)"
            $assessment = New-Assessment "UNKNOWN" "CHECK FAILED: $($_.Exception.Message)"
        }
        $color = switch ($assessment.Status) {
            "IMPLEMENTED" { "Green" }
            "NOT-CONFIGURED" { "Yellow" }
            "UNKNOWN" { "Cyan" }
        }
        Write-Host ("{0,2}. {1,-14} {2}" -f ($index + 1), $assessment.Status, $check.Title) -ForegroundColor $color
        Write-Host "    $($assessment.Details)"
        [pscustomobject]@{
            Number         = $index + 1
            Recommendation = $check.Title
            Status         = $assessment.Status
            Details        = $assessment.Details
            TenantId       = $TenantId.Guid
            CheckedAt      = $checkedAt
        }
    }
)

$implemented = @($results | Where-Object Status -eq "IMPLEMENTED").Count
$notConfigured = @($results | Where-Object Status -eq "NOT-CONFIGURED").Count
$unknown = @($results | Where-Object Status -eq "UNKNOWN").Count
Write-Host "`nSummary: $implemented implemented, $notConfigured not configured, $unknown unknown (11 recommendations)."
if ($PassThru) { $results }
