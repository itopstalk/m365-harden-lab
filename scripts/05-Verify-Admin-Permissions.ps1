#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Checks the signed-in administrator's permissions and assigns missing lab roles.

.DESCRIPTION
Run after scripts 00 and 01, before running configuration scripts. Checks the
built-in roles, delegated Graph scopes, modules, and service read access needed
by scripts 00-99. Uses Microsoft Graph v1.0 in the worldwide cloud.

Lists missing role coverage before offering permanent, active, tenant-wide role
assignments to the signed-in user. Each assignment requires confirmation.
Recognizes broader built-in roles and active role-assignable group membership.
Directory-role queries use directoryScopeId; appScopeId is not selected because
the directory provider rejects it even though it appears in the shared Graph schema.
Never assigns Global Administrator, changes group membership, or switches to a
different administrator. Without an active tenant-wide Privileged Role
Administrator or Global Administrator assignment, stops and reports the gaps.

PIM eligibility is not active access. Activate existing eligible roles before
running this script to avoid unnecessary permanent assignments. Custom roles
cannot be evaluated reliably across all services; missing built-in coverage
alongside a custom role requires manual review rather than automatic grants.

Graph scopes and Entra roles are separate requirements. Normal execution offers
to request the scopes used by the other scripts through interactive Graph
consent. It does not directly modify application permission grants. CheckOnly
and WhatIf request discovery/read scopes only and report other scopes absent
from the current token, which does not necessarily mean admin consent is absent.

Read probes do not modify policies or create test users. Write access is inferred
from documented roles and token scopes, not tested by changing configuration.
Licenses (including Entra P1/P2 for relevant features), provisioning, Conditional
Access, and each script's inputs and safeguards can still prevent execution.
Script 60 opens the SSPR Properties page; User Administrator covers that setting,
so Authentication Policy Administrator is not added just for opening that page.

New assignments are read back, but propagation and token refresh are still
required. Disconnect Graph and Teams and rerun after propagation. Partial grants
are not rolled back; a failed or unconfirmed write stops further assignments.
Returns one structured report, including Ready, MissingRoles, GraphPermissions,
AccessChecks, and AssignmentsCreated. Ready is false until all checks pass and
no newly assigned roles are awaiting a fresh sign-in.

.PARAMETER TenantId
The intended Microsoft Entra tenant GUID.

.PARAMETER CheckOnly
Report permissions and test read access without assigning roles or requesting
additional write scopes. Initial discovery can still require read-scope consent.

.PARAMETER UseGraphDeviceCode
Use device-code authentication for Microsoft Graph.

.PARAMETER UseTeamsDeviceAuthentication
Use device authentication for Microsoft Teams.

.EXAMPLE
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -CheckOnly

.EXAMPLE
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -WhatIf

.EXAMPLE
$report = .\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId
$report.MissingRoles

.LINK
https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
.LINK
https://learn.microsoft.com/entra/identity/role-based-access-control/delegate-by-task
.LINK
https://learn.microsoft.com/graph/api/rbacapplication-post-roleassignments
.LINK
https://learn.microsoft.com/graph/api/authorizationpolicy-update
.LINK
https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
.LINK
https://learn.microsoft.com/defender-xdr/microsoft-secure-score#secure-score-permissions
.LINK
https://learn.microsoft.com/microsoftteams/using-admin-roles
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -ne [guid]::Empty })]
    [guid] $TenantId,

    [switch] $CheckOnly,
    [switch] $UseGraphDeviceCode,
    [switch] $UseTeamsDeviceAuthentication
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

$roleTemplates = @{
    "Global Administrator"                = "62e90394-69f5-4237-9190-012177145e10"
    "Privileged Role Administrator"       = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "Conditional Access Administrator"    = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    "User Administrator"                  = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Directory Writers"                   = "9360feb5-f418-4baa-8175-e2a00bac4301"
    "Authentication Policy Administrator" = "0526716b-113d-4c15-b2c8-68e3c22b9f80"
    "Security Reader"                     = "5d6b6bb7-de71-4623-b4af-96380a352509"
    "Security Administrator"              = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "Security Operator"                   = "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"
    "Reports Reader"                      = "4a5d8f65-41da-4de4-8968-e035b65339cf"
    "Global Reader"                       = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    "Helpdesk Administrator"              = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    "Service Support Administrator"       = "f023fd81-a637-4b56-95fd-791ac0226033"
    "Exchange Administrator"              = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    "SharePoint Administrator"            = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    "Teams Communications Administrator"  = "baf37b3a-610e-45da-9e62-d9d1e5e8914b"
    "Teams Administrator"                 = "69091246-20e8-4a56-aa4d-066075b2a7a8"
}
$roleRequirements = @(
    @{
        Capability = "Security defaults and Conditional Access"
        Scripts = "02-03, 10-20, 99"
        Role = "Conditional Access Administrator"
        Alternatives = @("Security Administrator")
    }
    @{
        Capability = "Create emergency access users"
        Scripts = "04"
        Role = "User Administrator"
        Alternatives = @("Directory Writers")
    }
    @{
        Capability = "Assign roles and configure user application consent"
        Scripts = "04, 30-31, 50-52, 99"
        Role = "Privileged Role Administrator"
        Alternatives = @()
    }
    @{
        Capability = "Read authentication registration reports"
        Scripts = "11, 13, 61, 99"
        Role = "Security Reader"
        Alternatives = @("Reports Reader", "Security Administrator", "Global Reader")
    }
    @{
        Capability = "Read Microsoft Secure Score"
        Scripts = "11-19 (tests), 31, 41, 43, 45, 52, 61, 90"
        Role = "Security Reader"
        Alternatives = @(
            "Security Administrator", "Security Operator", "Global Reader",
            "User Administrator", "Helpdesk Administrator", "Service Support Administrator",
            "Exchange Administrator", "SharePoint Administrator"
        )
    }
    @{
        Capability = "Manage Teams meeting policies"
        Scripts = "01 -IncludeTeams, 40-45, 99"
        Role = "Teams Communications Administrator"
        Alternatives = @("Teams Administrator")
    }
    @{
        Capability = "Configure SSPR Properties in the portal"
        Scripts = "60"
        Role = "User Administrator"
        Alternatives = @("Authentication Policy Administrator")
    }
)
$requiredScopes = @(
    "AuditLog.Read.All"
    "Directory.Read.All"
    "Domain.Read.All"
    "Policy.Read.All"
    "Policy.ReadWrite.Authorization"
    "Policy.ReadWrite.ConditionalAccess"
    "Policy.ReadWrite.SecurityDefaults"
    "RoleManagement.Read.Directory"
    "RoleManagement.ReadWrite.Directory"
    "SecurityEvents.Read.All"
    "User.Create"
    "User.Read.All"
)
$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.Governance"
    "MicrosoftTeams"
)

function Get-PermissionErrorDetail {
    param([System.Management.Automation.ErrorRecord] $Record)
    $details = $Record.Exception.Message
    if (-not [string]::IsNullOrWhiteSpace($Record.ErrorDetails.Message)) {
        $details += " $($Record.ErrorDetails.Message)"
    }
    $details
}

function Get-VerifiedAdminIdentity {
    param([string] $ExpectedId)
    $currentContext = Get-MgContext
    if (
        $null -eq $currentContext -or $currentContext.TenantId -ne $TenantId.Guid -or
        $currentContext.AuthType -ne "Delegated" -or $currentContext.Environment -ne "Global"
    ) {
        throw "A delegated Microsoft Graph connection to the intended worldwide tenant is required."
    }
    $identity = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName,accountEnabled' -ErrorAction Stop
    $id = [guid]::Empty
    if (
        -not [guid]::TryParse([string] $identity.id, [ref] $id) -or $id -eq [guid]::Empty -or
        [string]::IsNullOrWhiteSpace($identity.userPrincipalName) -or
        $identity.accountEnabled -isnot [bool] -or -not $identity.accountEnabled
    ) {
        throw "Graph did not identify an enabled signed-in user. No roles will be assigned."
    }
    if ($ExpectedId -and $identity.id -ne $ExpectedId) {
        Disconnect-MgGraph -ErrorAction Stop | Out-Null
        throw "The Graph account changed during verification. Sign in as the original account; no further roles will be assigned."
    }
    $identity
}

function Get-AdminActiveRoles {
    $principalIds = @{ $admin.id = "Direct" }
    # Role-assignable groups cannot contain nested groups; direct memberships suffice.
    $memberships = @(Get-SecureM365GraphCollection -Uri 'https://graph.microsoft.com/v1.0/me/memberOf?$select=id')
    foreach ($membership in $memberships) {
        if ([string]::IsNullOrWhiteSpace($membership.id) -or -not $membership.'@odata.type') {
            throw "Graph returned an incomplete membership inventory; role coverage cannot be determined."
        }
        if ($membership.'@odata.type' -eq "#microsoft.graph.group") {
            $principalIds[$membership.id] = "Group $($membership.id)"
        }
    }
    $assignments = @(Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId')
    foreach ($assignment in $assignments) {
        if ([string]::IsNullOrWhiteSpace($assignment.principalId)) {
            throw "Graph returned a role assignment without a principal ID."
        }
        if (-not $principalIds.ContainsKey($assignment.principalId)) { continue }
        $role = $definitionsById[$assignment.roleDefinitionId]
        if ($null -eq $role -or [string]::IsNullOrWhiteSpace($assignment.directoryScopeId)) {
            throw "An active assignment has an unresolved role or missing scope; no role changes are safe."
        }
        [pscustomobject]@{
            Role = $role.displayName
            TemplateId = $role.templateId
            IsBuiltIn = $role.isBuiltIn
            TenantWide = $assignment.directoryScopeId -eq "/" -and -not $assignment.appScopeId
            DirectoryScopeId = $assignment.directoryScopeId
            Source = $principalIds[$assignment.principalId]
        }
    }
}

function Get-RoleCoverage {
    param([string[]] $TemplateIds)
    foreach ($requirement in $roleRequirements) {
        $accepted = @($requirement.Role) + $requirement.Alternatives + @("Global Administrator")
        $satisfiedBy = @($accepted | Where-Object { $roleTemplates[$_] -in $TemplateIds })
        [pscustomobject]@{
            Capability = $requirement.Capability
            Scripts = $requirement.Scripts
            Role = $requirement.Role
            Status = if ($satisfiedBy.Count -gt 0) { "PRESENT" } else { "MISSING" }
            SatisfiedBy = $satisfiedBy -join ", "
        }
    }
}

function Get-MissingRolePlan {
    param([string[]] $TemplateIds)
    $plannedIds = @($TemplateIds)
    foreach ($requirement in $roleRequirements) {
        $accepted = @($requirement.Role) + $requirement.Alternatives + @("Global Administrator")
        if (@($accepted | Where-Object { $roleTemplates[$_] -in $plannedIds }).Count -eq 0) {
            $requirement.Role
            $plannedIds += $roleTemplates[$requirement.Role]
        }
    }
}

function Get-GraphPermissionCoverage {
    $tokenScopes = @( (Get-MgContext).Scopes )
    foreach ($scope in $requiredScopes) {
        [pscustomobject]@{
            Scope = $scope
            Status = if ($scope -in $tokenScopes) { "IN TOKEN" } else { "NOT IN TOKEN" }
        }
    }
}

$null = Connect-SecureM365Graph -TenantId $TenantId `
    -AdditionalScopes "Directory.Read.All" -UseDeviceCode:$UseGraphDeviceCode
$admin = Get-VerifiedAdminIdentity
Write-Host "`nChecking $($admin.userPrincipalName) ($($admin.id)) in tenant $($TenantId.Guid)"

$modules = @(
    foreach ($name in $requiredModules) {
        [pscustomobject]@{
            Module = $name
            Installed = [bool] (Get-Module -ListAvailable -Name $name)
        }
    }
)
$definitionsById = @{}
$definitionsByTemplate = @{}
try {
    $definitions = @(Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn')
    if ($definitions.Count -eq 0) {
        throw "Graph returned no role definitions; an empty inventory cannot verify permissions."
    }
    foreach ($role in $definitions) {
        if (
            [string]::IsNullOrWhiteSpace($role.id) -or
            [string]::IsNullOrWhiteSpace($role.displayName) -or $role.isBuiltIn -isnot [bool] -or
            $definitionsById.ContainsKey($role.id)
        ) {
            throw "Graph returned an incomplete or duplicate role definition."
        }
        $definitionsById[$role.id] = $role
        if ($role.isBuiltIn) {
            if ([string]::IsNullOrWhiteSpace($role.templateId) -or $definitionsByTemplate.ContainsKey($role.templateId)) {
                throw "Graph returned a missing or duplicate built-in role template ID."
            }
            $definitionsByTemplate[$role.templateId] = $role
        }
    }
    $activeRoles = @(Get-AdminActiveRoles)
}
catch {
    throw "Cannot safely inventory administrator roles. No roles were assigned. For authorization failures, check RoleManagement.Read.Directory / Directory.Read.All consent and directory read access. Graph error: $(Get-PermissionErrorDetail $_)"
}
$effectiveIds = @($activeRoles | Where-Object { $_.TenantWide -and $_.IsBuiltIn } | ForEach-Object { $_.TemplateId })
$roleCoverage = @(Get-RoleCoverage -TemplateIds $effectiveIds)
$missingRoles = @(Get-MissingRolePlan -TemplateIds $effectiveIds)
$graphPermissions = @(Get-GraphPermissionCoverage)
$canAssignRoles = $roleTemplates["Privileged Role Administrator"] -in $effectiveIds -or
    $roleTemplates["Global Administrator"] -in $effectiveIds
$blockedReason = $null
$created = [System.Collections.Generic.List[object]]::new()
$accessChecks = [System.Collections.Generic.List[object]]::new()

Write-Host "`nRequired role coverage (active, tenant-wide built-in roles):"
$roleCoverage | Format-Table Role, Status, SatisfiedBy, Capability, Scripts -Wrap | Out-Host
Write-Host "Graph permissions absent from this token may already have consent; each script requests its own scopes."
$graphPermissions | Format-Table Scope, Status -AutoSize | Out-Host
if ($missingRoles.Count -gt 0) {
    Write-Warning "Missing role coverage can be supplied by: $($missingRoles -join ', '). PIM eligibility and scoped assignments do not provide active tenant-wide access."
}
if (-not $canAssignRoles) {
    $blockedReason = "The account has no active tenant-wide Privileged Role Administrator or Global Administrator role. Ask an existing authorized administrator to grant the listed roles, or activate an existing eligible role and rerun. This script will not switch accounts or elevate an unauthorized account."
}
elseif ($missingRoles.Count -gt 0 -and @($activeRoles | Where-Object { -not $_.IsBuiltIn }).Count -gt 0) {
    $blockedReason = "Custom role assignments need manual review. Missing built-in coverage is not proof that a custom role lacks permissions; no automatic assignments will be made."
}

if ($blockedReason) {
    Write-Warning $blockedReason
}
elseif (-not $CheckOnly) {
    foreach ($name in $missingRoles) {
        if (-not $definitionsByTemplate.ContainsKey($roleTemplates[$name])) {
            throw "Cannot resolve the built-in role '$name'. No roles were assigned."
        }
    }
    $missingScopes = @($graphPermissions | Where-Object Status -eq "NOT IN TOKEN" | ForEach-Object { $_.Scope })
    if (
        $missingScopes.Count -gt 0 -and
        $PSCmdlet.ShouldProcess($admin.userPrincipalName, "Request delegated Graph scopes through interactive consent: $($missingScopes -join ', ')")
    ) {
        $null = Connect-SecureM365Graph -TenantId $TenantId `
            -AdditionalScopes $requiredScopes -UseDeviceCode:$UseGraphDeviceCode
        $null = Get-VerifiedAdminIdentity -ExpectedId $admin.id
        $graphPermissions = @(Get-GraphPermissionCoverage)
    }

    $writeAttempted = $false
    $completed = $false
    try {
        foreach ($name in $missingRoles) {
            $target = "$($admin.userPrincipalName) ($($admin.id)), tenant $($TenantId.Guid)"
            if (-not $PSCmdlet.ShouldProcess($target, "Assign permanent active tenant-wide '$name' role (not PIM eligibility)")) {
                continue
            }
            $null = Get-VerifiedAdminIdentity -ExpectedId $admin.id
            if ("RoleManagement.ReadWrite.Directory" -notin (Get-MgContext).Scopes) {
                throw "The current Graph token lacks RoleManagement.ReadWrite.Directory. Consent was not completed; no further roles will be assigned."
            }
            $currentRoles = @(Get-AdminActiveRoles)
            $currentIds = @($currentRoles | Where-Object { $_.TenantWide -and $_.IsBuiltIn } | ForEach-Object { $_.TemplateId })
            if (
                $roleTemplates["Privileged Role Administrator"] -notin $currentIds -and
                $roleTemplates["Global Administrator"] -notin $currentIds
            ) {
                throw "Role-assignment authority is no longer active. No further roles will be assigned."
            }
            if ($name -notin @(Get-MissingRolePlan -TemplateIds $currentIds)) {
                Write-Host "Already covered: $name"
                continue
            }
            $definition = $definitionsByTemplate[$roleTemplates[$name]]
            $body = @{
                principalId = $admin.id
                roleDefinitionId = $definition.id
                directoryScopeId = "/"
            } | ConvertTo-Json
            $writeAttempted = $true
            $assignment = Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' `
                -Body $body -ContentType "application/json" -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($assignment.id)) {
                throw "The '$name' assignment was not confirmed. Check the tenant before retrying."
            }
            $assignmentId = [uri]::EscapeDataString($assignment.id)
            $persisted = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$assignmentId" -ErrorAction Stop
            foreach ($record in @($assignment, $persisted)) {
                if (
                    $null -eq $record -or $record.id -ne $assignment.id -or
                    $record.principalId -ne $admin.id -or $record.roleDefinitionId -ne $definition.id -or
                    $record.directoryScopeId -ne "/" -or $record.appScopeId
                ) {
                    throw "The returned '$name' assignment did not match the intended user, role, and tenant-wide scope. Review it before retrying."
                }
            }
            [void] $created.Add([pscustomobject]@{ Role = $name; AssignmentId = $assignment.id })
            Write-Host "Assigned and read back: $name"
        }
        $completed = $true
    }
    catch {
        throw "Permission remediation stopped. $(Get-PermissionErrorDetail $_)"
    }
    finally {
        if ($writeAttempted -and -not $completed) {
            Write-Warning "A role write was attempted. No changes were rolled back. Check the account before retrying, including requests whose outcome is unknown."
            foreach ($item in $created) {
                Write-Warning "Confirmed assignment: '$($item.Role)' ($($item.AssignmentId))."
            }
        }
    }
}

if ($created.Count -gt 0) {
    $activeRoles = @(Get-AdminActiveRoles)
    $effectiveIds = @($activeRoles | Where-Object { $_.TenantWide -and $_.IsBuiltIn } | ForEach-Object { $_.TemplateId })
    $roleCoverage = @(Get-RoleCoverage -TemplateIds $effectiveIds)
    $missingRoles = @(Get-MissingRolePlan -TemplateIds $effectiveIds)
    Write-Warning "New assignments require propagation and fresh tokens. Run Disconnect-MgGraph and Disconnect-MicrosoftTeams, then rerun this script. Ready remains false for this run."
}

if (-not $blockedReason) {
    $probes = @(
        @{ Name = "Security defaults"; Path = "policies/identitySecurityDefaultsEnforcementPolicy"; Property = "isEnabled" }
        @{ Name = "Conditional Access"; Path = "identity/conditionalAccess/policies"; Property = "value" }
        @{ Name = "User inventory"; Path = 'users?$select=id&$top=1'; Property = "value" }
        @{ Name = "Initial domain inventory"; Path = 'domains?$select=id'; Property = "value" }
        @{ Name = "Authorization policy"; Path = "policies/authorizationPolicy"; Property = "id" }
        @{ Name = "Authentication registration report"; Path = "reports/authenticationMethods/userRegistrationDetails"; Property = "value" }
        @{ Name = "Secure Score"; Path = 'security/secureScores?$top=1'; Property = "value" }
        @{ Name = "Secure Score control profiles"; Path = 'security/secureScoreControlProfiles?$top=1'; Property = "value" }
    )
    foreach ($probe in $probes) {
        $status = "PASSED"
        $details = "Read access verified; this probe does not assess configuration or complete inventory."
        try {
            $response = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/$($probe.Path)" -ErrorAction Stop
            if ($null -eq $response -or $null -eq $response.($probe.Property)) {
                throw "The response did not contain '$($probe.Property)'."
            }
        }
        catch {
            $status = "FAILED"
            $details = Get-PermissionErrorDetail $_
            Write-Warning "$($probe.Name) read failed: $details"
        }
        [void] $accessChecks.Add([pscustomobject]@{ Service = $probe.Name; Status = $status; Details = $details })
    }

    $teamsStatus = "PASSED"
    $teamsDetails = "Meeting-policy read access verified using the same account as Microsoft Graph."
    try {
        if (-not ($modules | Where-Object Module -eq "MicrosoftTeams").Installed) {
            throw "MicrosoftTeams is not installed. Run script 00."
        }
        $connection = Connect-SecureM365Teams -TenantId $TenantId -UseDeviceAuthentication:$UseTeamsDeviceAuthentication
        if ([string]::IsNullOrWhiteSpace([string] $connection.Account)) {
            throw "Teams did not return the signed-in account; its identity cannot be verified."
        }
        if ([string] $connection.Account -ne $admin.userPrincipalName) {
            $teamsAccount = [uri]::EscapeDataString([string] $connection.Account)
            $teamsUser = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users/$teamsAccount`?`$select=id" -ErrorAction Stop
            if ($teamsUser.id -ne $admin.id) {
                Disconnect-MicrosoftTeams -ErrorAction Stop | Out-Null
                throw "Teams signed in as a different account. Reconnect Teams as '$($admin.userPrincipalName)'."
            }
        }
        $policies = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop)
        if (@($policies | Where-Object Identity -eq "Global").Count -ne 1) {
            throw "Teams did not return the Global meeting policy."
        }
    }
    catch {
        $teamsStatus = "FAILED"
        $teamsDetails = Get-PermissionErrorDetail $_
        Write-Warning "Teams access failed: $teamsDetails Verify active Teams roles, provisioning, and sign-in; Graph consent does not grant Teams access."
    }
    [void] $accessChecks.Add([pscustomobject]@{ Service = "Teams meeting policies"; Status = $teamsStatus; Details = $teamsDetails })
}

$missingModules = @($modules | Where-Object { -not $_.Installed } | ForEach-Object { $_.Module })
$missingScopes = @($graphPermissions | Where-Object Status -eq "NOT IN TOKEN" | ForEach-Object { $_.Scope })
$ready = -not $blockedReason -and $missingRoles.Count -eq 0 -and $missingScopes.Count -eq 0 -and
    $missingModules.Count -eq 0 -and $created.Count -eq 0 -and
    $accessChecks.Count -eq 9 -and @($accessChecks | Where-Object Status -ne "PASSED").Count -eq 0
if ($missingModules.Count -gt 0) {
    Write-Warning "Missing modules: $($missingModules -join ', '). Run script 00; this script does not install tools."
}
Write-Host "`nService read checks:"
$accessChecks | Format-Table Service, Status, Details -Wrap | Out-Host
Write-Host "Permission readiness: $ready | Roles assigned: $($created.Count) | Missing roles: $($missingRoles.Count) | Scopes not in token: $($missingScopes.Count)"
Write-Host "Licensing, provisioning, Conditional Access, and script-specific prerequisites still apply. No configuration write tests were performed."

[pscustomobject]@{
    TenantId = $TenantId.Guid
    Account = $admin.userPrincipalName
    UserId = $admin.id
    CheckedAt = [datetimeoffset]::UtcNow
    Ready = $ready
    CanAssignRoles = $canAssignRoles
    BlockedReason = $blockedReason
    ActiveRoles = $activeRoles
    RoleCoverage = $roleCoverage
    MissingRoles = $missingRoles
    GraphPermissions = $graphPermissions
    Modules = $modules
    AccessChecks = $accessChecks.ToArray()
    AssignmentsCreated = $created.ToArray()
    RequiresReconnect = $created.Count -gt 0
}
