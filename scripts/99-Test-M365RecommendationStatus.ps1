#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, MicrosoftTeams

<#
.SYNOPSIS
Displays the live status of the 10 Microsoft 365 recommendations in the guide.

.DESCRIPTION
Run after scripts 00 and 01. Uses read-only Microsoft Graph v1.0 and Teams queries,
not Secure Score snapshots. Prints green IMPLEMENTED, yellow NOT-CONFIGURED, or
cyan UNKNOWN, followed by evidence or the reason a check could not be completed.
Report-only and disabled Conditional Access policies do not count as enforced.
Complex combinations of narrower policies may need manual review.
Every run also writes the structured results to a timestamped JSON file under
C:\SecureM365Snapshots by default, creating that directory when necessary.

The two MFA recommendations check for enabled MFA configuration, not complete
coverage or user registration. Administrator MFA matches a policy targeting
directory roles or all users; all-user MFA requires a policy targeting All users.
Security Defaults also satisfies these configuration checks. Policy names, IDs,
states, exclusions, and a separate coverage advisory are included in the evidence.
An IMPLEMENTED MFA result does not prove every account or sign-in is protected.
For SSPR, Microsoft Graph does not expose the exact Password reset > Properties
scope. SsprAllScopeConfirmed defaults to true, recording the lab operator's
confirmation without requiring a flag on every run. Set it explicitly to false
for a tenant where All has not been verified. Authentication-method registration
data is included as an advisory readiness note for MFA and SSPR and does not
downgrade verified configuration evidence. The registration report requires Entra ID
P1/P2 and can lag changes by up to 36 hours.
Teams checks intentionally assess only the org-wide Global meeting policy, which
scripts 40, 42, and 44 configure. Custom meeting policies and their user/group
assignments require separate review and are outside these checks.

.PARAMETER TenantId
Target tenant in the worldwide cloud. If omitted, uses the delegated Graph tenant
connected by script 01 in this PowerShell process. Each service connection is
checked against that tenant before its configuration is read.

.PARAMETER ApprovedExcludedUserId
Explicitly approved Conditional Access user exclusions, such as the object IDs
returned by script 04. For MFA, these affect only the coverage advisory, not
policy detection. Other Conditional Access recommendations still require approved
exclusions. Does not omit these users from the registration advisory.

.PARAMETER ApprovedExcludedGroupId
Explicitly approved Conditional Access group exclusions.

.PARAMETER ApprovedExcludedRoleId
Explicitly approved Conditional Access exclusions, using role template IDs.

.PARAMETER SnapshotDirectory
Directory for the timestamped JSON snapshot. Defaults to
C:\SecureM365Snapshots and is created when it does not exist.

.PARAMETER SsprAllScopeConfirmed
Defaults to true based on the lab operator's confirmation that Entra ID >
Password reset > Properties is set to All. Microsoft Graph does not expose that
exact tenant setting. Use -SsprAllScopeConfirmed:$false for another tenant or
whenever All has not been verified. Per-user registration and capability data
is reported only as advisory evidence.

.PARAMETER UseGraphDeviceCode
Use device-code authentication for Microsoft Graph.

.PARAMETER UseTeamsDeviceAuthentication
Use device authentication for Microsoft Teams.

.PARAMETER TeamsApplicationId
Use the dedicated Teams application with exactly one certificate parameter.

.PARAMETER TeamsCertificateThumbprint
Thumbprint in Cert:\CurrentUser\My for the Teams application certificate.

.PARAMETER TeamsCertificatePath
Path to a PFX outside this repository.

.PARAMETER PassThru
Also return the 10 structured result objects for filtering or export. Each
result includes Evidence; Details contains the same value for compatibility.
MFA results also include PolicyConfiguration with PolicyFound, EnabledPolicyFound,
CoverageVerified, and matching policy details. These are also saved in the snapshot.

.NOTES
The script loads its datasets before printing check 1, so data-read warnings can
appear before the first check. A failed read leaves dependent checks UNKNOWN.

Before running this report, use script 01 with -IncludeTeams to verify Teams
meeting-policy read access. Installing modules or consenting to Microsoft Graph
scopes does not grant Teams permissions. For Teams Forbidden/Access Denied, verify
the Teams account has an active role permitted to read meeting policies, such as
Teams Communications Administrator. If using PIM, activate the role, allow it to
propagate, then run Disconnect-MicrosoftTeams and rerun script 01 -IncludeTeams.

.EXAMPLE
.\99-Test-M365RecommendationStatus.ps1

.EXAMPLE
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

.EXAMPLE
$results = .\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -PassThru

.EXAMPLE
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -SsprAllScopeConfirmed:$false
#>

[CmdletBinding()]
param(
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,

    [guid[]] $ApprovedExcludedUserId = @(),
    [guid[]] $ApprovedExcludedGroupId = @(),
    [guid[]] $ApprovedExcludedRoleId = @(),
    [string] $SnapshotDirectory = "C:\SecureM365Snapshots",
    [switch] $SsprAllScopeConfirmed = $true,
    [Alias("UseDeviceCode")]
    [switch] $UseGraphDeviceCode,
    [switch] $UseTeamsDeviceAuthentication,
    [guid] $TeamsApplicationId,
    [string] $TeamsCertificateThumbprint,
    [string] $TeamsCertificatePath,
    [securestring] $TeamsCertificatePassword,
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
        [string] $Details,

        [psobject] $PolicyConfiguration
    )
    [pscustomobject]@{
        Status   = $Status
        Evidence = $Details
        # Retained for consumers of earlier script versions.
        Details  = $Details
        PolicyConfiguration = $PolicyConfiguration
    }
}

function Save-RecommendationSnapshot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object[]] $Results,

        [Parameter(Mandatory)]
        [guid] $TenantId,

        [Parameter(Mandatory)]
        [datetimeoffset] $CheckedAt,

        [Parameter(Mandatory)]
        [string] $Directory
    )

    if ([string]::IsNullOrWhiteSpace($Directory)) {
        throw "SnapshotDirectory cannot be empty."
    }
    if (Test-Path -LiteralPath $Directory) {
        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
            throw "SnapshotDirectory '$Directory' exists but is not a directory."
        }
    }
    else {
        $null = New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop
    }

    $resolvedDirectory = (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path
    $timestamp = $CheckedAt.UtcDateTime.ToString("yyyyMMdd-HHmmssfff'Z'")
    $snapshotPath = Join-Path `
        $resolvedDirectory `
        "$($TenantId.Guid)-m365-recommendation-status-$timestamp.json"
    if (Test-Path -LiteralPath $snapshotPath) {
        throw "Snapshot '$snapshotPath' already exists and will not be overwritten."
    }

    ConvertTo-Json -InputObject @($Results) -Depth 8 |
        Set-Content -LiteralPath $snapshotPath -Encoding utf8 -ErrorAction Stop
    (Resolve-Path -LiteralPath $snapshotPath -ErrorAction Stop).Path
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

    Test-SecureM365CaRequiresMfa $Policy
}

function Test-ReportPolicyScope {
    param(
        [Parameter(Mandatory)] $Policy,
        [ValidateSet("None", "SignIn", "User")] [string] $Risk = "None",
        [switch] $Legacy
    )

    Test-SecureM365CaPolicyScope -Policy $Policy -ApprovedExclusions $approvedExclusions `
        -Risk $Risk -Legacy:$Legacy
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
        $assignments = @(Get-CheckData "RoleAssignments")
        if (@($assignments | Where-Object { [string]::IsNullOrWhiteSpace($_.principalId) }).Count -gt 0) {
            throw "An active role assignment omitted its principal ID."
        }
        # Direct user assignments supplement the registration report. Non-user
        # principals cannot register MFA; group-based admins are identified by isAdmin.
        $directAdminIds = @(
            $assignments.principalId |
                Where-Object { $_ -in @($users.id) } |
                Sort-Object -Unique
        )
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
    $policyReadFailed = $securityDefaults -and $readFailures.ContainsKey("ConditionalAccess")
    $policies = @(if (-not $policyReadFailed) { Get-CheckData "ConditionalAccess" })
    $parameters = @{
        Policies = @($policies)
        SecurityDefaultsEnabled = $securityDefaults
        Administrators = $Administrators
        ApprovedExclusions = $approvedExclusions
    }
    $policyAssessment = Get-SecureM365MfaPolicyAssessment @parameters
    if ($Administrators -and $null -eq $policyAssessment.CoverageVerified) {
        try {
            $roles = @(Get-CheckData "RoleDefinitions")
            $assignments = @(Get-CheckData "RoleAssignments")
            if ($assignments.Count -eq 0) { throw "No active role assignments were returned." }
            $parameters.RequiredRoleIds = @(
                foreach ($assignment in $assignments) {
                    $role = @($roles | Where-Object { $_.id -eq $assignment.roleDefinitionId })
                    if (
                        $role.Count -ne 1 -or
                        $role[0].isBuiltIn -ne $true -or
                        [string]::IsNullOrWhiteSpace($role[0].templateId)
                    ) {
                        throw "An assigned role could not be resolved to a built-in template."
                    }
                    $role[0].templateId
                }
            ) | Select-Object -Unique
        }
        catch {
            $parameters.CoverageReadError = $_.Exception.Message
            Write-Warning "Administrator MFA coverage could not be evaluated: $($parameters.CoverageReadError)"
        }
        $policyAssessment = Get-SecureM365MfaPolicyAssessment @parameters
    }
    if ($policyReadFailed) {
        $policyAssessment.PolicyFound = $null
        $policyAssessment.EnabledPolicyFound = $null
        $policyAssessment.Evidence += " Conditional Access policy inventory is unavailable: $($readFailures['ConditionalAccess']). Security Defaults independently verifies the MFA configuration."
    }
    if ($policyAssessment.Status -ne "IMPLEMENTED") {
        return New-Assessment $policyAssessment.Status $policyAssessment.Evidence `
            -PolicyConfiguration $policyAssessment
    }

    try {
        $coverage = @(Get-RegistrationCoverage -Administrators:$Administrators)
        $missing = @($coverage | Where-Object { $_.Registration.isMfaCapable -isnot [bool] })
        $notCapable = @($coverage | Where-Object { $_.Registration.isMfaCapable -eq $false })
        $registrationNote = if ($notCapable.Count -gt 0 -or $missing.Count -gt 0) {
            "Registration advisory: $($notCapable.Count) of $($coverage.Count) checked enabled accounts are not reported MFA-capable and $($missing.Count) have missing data. Registration data can lag by up to 36 hours and does not determine the enabled-policy result."
        }
        else {
            "Registration advisory: all $($coverage.Count) checked enabled accounts are reported MFA-capable, including any emergency accounts."
        }
    }
    catch {
        $registrationNote = "Registration advisory: readiness data could not be verified and can lag by up to 36 hours. The enabled-policy result is unchanged. $($_.Exception.Message)"
    }

    New-Assessment "IMPLEMENTED" "$($policyAssessment.Evidence) $registrationNote" `
        -PolicyConfiguration $policyAssessment
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

    $policy = Get-CheckData "Teams"
    if ($null -eq $policy.$Property) {
        throw "Teams did not return '$Property' on the Global meeting policy."
    }
    if ($Expected -is [bool] -and $policy.$Property -isnot [bool]) {
        throw "Teams returned a non-Boolean '$Property' value for the Global meeting policy."
    }
    if ($policy.$Property -ne $Expected) {
        return New-Assessment "NOT-CONFIGURED" "Global: $Property is '$($policy.$Property)'; expected '$Expected'."
    }
    New-Assessment "IMPLEMENTED" "Global: $Property is '$Expected'."
}

function Get-SsprAssessment {
    try {
        $coverage = @(Get-RegistrationCoverage)
        $registered = @($coverage | Where-Object { $_.Registration.isSsprRegistered -eq $true })
        $notRegistered = @($coverage | Where-Object { $_.Registration.isSsprRegistered -eq $false })
        $missingRegistration = @(
            $coverage | Where-Object { $_.Registration.isSsprRegistered -isnot [bool] }
        )
        $capable = @($coverage | Where-Object { $_.Registration.isSsprCapable -eq $true })
        $notCapable = @($coverage | Where-Object { $_.Registration.isSsprCapable -eq $false })
        $missingCapability = @(
            $coverage | Where-Object { $_.Registration.isSsprCapable -isnot [bool] }
        )
        $registrationNote = "Registration note: $($registered.Count) of $($coverage.Count) enabled member accounts are reported SSPR-registered; $($notRegistered.Count) are not registered and $($missingRegistration.Count) have missing registration data. $($capable.Count) are reported SSPR-capable; $($notCapable.Count) are not capable and $($missingCapability.Count) have missing capability data. Registration data can lag by up to 36 hours."
    }
    catch {
        $registrationNote = "Registration note: readiness data could not be verified and can lag by up to 36 hours. $($_.Exception.Message)"
    }

    if (-not $SsprAllScopeConfirmed) {
        return New-Assessment "UNKNOWN" "Password reset > Properties = All has not been operator-confirmed. Microsoft Graph does not expose the exact None, Selected, or All scope. Confirm the setting in Entra, then rerun with -SsprAllScopeConfirmed. $registrationNote"
    }
    New-Assessment "IMPLEMENTED" "Password reset > Properties = All is recorded as operator-confirmed by the script default. $registrationNote"
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
    # Role-management endpoints do not support $top; the collection helper follows nextLink.
    RoleDefinitions = {
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn'
    }
    RoleAssignments = {
        # The directory provider rejects appScopeId in $select; scope is directoryScopeId.
        Get-SecureM365GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId'
    }
    Authorization = {
        Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -ErrorAction Stop
    }
    Teams = {
        Connect-SecureM365Teams -TenantId $TenantId -ValidateMeetingPolicyAccess `
            -UseDeviceAuthentication:$UseTeamsDeviceAuthentication `
            -ApplicationId $TeamsApplicationId `
            -CertificateThumbprint $TeamsCertificateThumbprint `
            -CertificatePath $TeamsCertificatePath `
            -CertificatePassword $TeamsCertificatePassword | Out-Null
        Get-SecureM365TeamsMeetingPolicy
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
        if (-not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
            $readFailures[$name] += " $($_.ErrorDetails.Message)"
        }
        Write-Warning "Could not read ${name}: $($readFailures[$name]). Dependent checks will report UNKNOWN unless other evidence is sufficient."
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
        Title = "Ensure 'Self service password reset enabled' is set to 'All'"
        Evaluate = { Get-SsprAssessment }
    }
)

$checkedAt = [datetimeoffset]::UtcNow
Write-Host "`nMicrosoft 365 live recommendation status"
Write-Host "Tenant: $($TenantId.Guid) | Checked at: $($checkedAt.ToString('u'))"
Write-Host "MFA results check enabled configuration; complete coverage and registration are advisory."
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
        [pscustomobject]@{
            Number         = $index + 1
            Recommendation = $check.Title
            Status         = $assessment.Status
            Evidence       = $assessment.Evidence
            # Retained for consumers of earlier script versions.
            Details        = $assessment.Evidence
            PolicyConfiguration = $assessment.PolicyConfiguration
            TenantId       = $TenantId.Guid
            CheckedAt      = $checkedAt
        }
    }
)

$snapshotPath = Save-RecommendationSnapshot `
    -Results $results `
    -TenantId $TenantId `
    -CheckedAt $checkedAt `
    -Directory $SnapshotDirectory

$results |
    Format-Table Number, Status, Recommendation, Evidence -Wrap |
    Out-Host

$implemented = @($results | Where-Object Status -eq "IMPLEMENTED").Count
$notConfigured = @($results | Where-Object Status -eq "NOT-CONFIGURED").Count
$unknown = @($results | Where-Object Status -eq "UNKNOWN").Count
Write-Host "`nSummary: $implemented implemented, $notConfigured not configured, $unknown unknown ($($checks.Count) recommendations)."
Write-Host "Snapshot: $snapshotPath"
if ($PassThru) { $results }
