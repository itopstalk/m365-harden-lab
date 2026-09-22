#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [guid] $PrincipalObjectId,

    [Parameter(Mandatory)]
    [string] $ObsoleteAssignmentId,

    [Parameter(Mandatory)]
    [string] $ReplacementRoleName,

    [string] $DirectoryScopeId = "/",
    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes @(
        "RoleManagement.ReadWrite.Directory"
        "Directory.Read.All"
    ) `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
$replacementRole = @(
    $roleDefinitions |
    Where-Object { $_.DisplayName -eq $ReplacementRoleName }
)
if ($replacementRole.Count -ne 1) {
    throw "Expected one role named '$ReplacementRoleName' but found $($replacementRole.Count)."
}
$replacementRole = $replacementRole[0]

$obsoleteAssignment = Get-MgRoleManagementDirectoryRoleAssignment `
    -UnifiedRoleAssignmentId $ObsoleteAssignmentId `
    -ErrorAction Stop
if ($obsoleteAssignment.PrincipalId -ne $PrincipalObjectId.Guid) {
    throw "The obsolete assignment belongs to '$($obsoleteAssignment.PrincipalId)', not '$($PrincipalObjectId.Guid)'."
}

$obsoleteRole = $roleDefinitions |
    Where-Object { $_.Id -eq $obsoleteAssignment.RoleDefinitionId } |
    Select-Object -First 1
if ($null -eq $obsoleteRole) {
    throw "The obsolete role definition was not found."
}
$obsoleteScope = if ($obsoleteAssignment.DirectoryScopeId) {
    $obsoleteAssignment.DirectoryScopeId
}
else {
    "/"
}
if (
    $obsoleteRole.Id -eq $replacementRole.Id -and
    $obsoleteScope -eq $DirectoryScopeId
) {
    throw "The replacement role and scope are identical to the obsolete assignment."
}

if ($obsoleteRole.DisplayName -eq "Global Administrator") {
    $globalAdminAssignments = @(
        Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop |
        Where-Object { $_.RoleDefinitionId -eq $obsoleteRole.Id }
    )
    if ($globalAdminAssignments.Count -le 2) {
        throw "Removing this assignment would leave fewer than two active Global Administrator assignments."
    }
}

$existingReplacement = @(
    Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop |
    Where-Object {
        $assignmentScope = if ($_.DirectoryScopeId) {
            $_.DirectoryScopeId
        }
        else {
            "/"
        }

        $_.PrincipalId -eq $PrincipalObjectId.Guid -and
        $_.RoleDefinitionId -eq $replacementRole.Id -and
        $assignmentScope -eq $DirectoryScopeId
    }
) | Select-Object -First 1

$description = "Assign '$ReplacementRoleName' and remove '$($obsoleteRole.DisplayName)' assignment '$ObsoleteAssignmentId'"
if ($PSCmdlet.ShouldProcess($PrincipalObjectId.Guid, $description)) {
    $replacement = $existingReplacement
    if ($null -eq $replacement) {
        $replacement = New-MgRoleManagementDirectoryRoleAssignment `
            -BodyParameter @{
                principalId      = $PrincipalObjectId.Guid
                roleDefinitionId = $replacementRole.Id
                directoryScopeId = $DirectoryScopeId
            } `
            -ErrorAction Stop
    }

    if ($null -eq $replacement.Id) {
        throw "The replacement assignment was not confirmed; the obsolete assignment was retained."
    }

    Remove-MgRoleManagementDirectoryRoleAssignment `
        -UnifiedRoleAssignmentId $ObsoleteAssignmentId `
        -ErrorAction Stop

    $replacement |
        Select-Object Id, PrincipalId, RoleDefinitionId, DirectoryScopeId
}
