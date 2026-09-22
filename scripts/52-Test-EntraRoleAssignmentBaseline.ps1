#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ApprovedBaselinePath,

    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Directory.Read.All" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$approvedAssignments = @(Import-Csv -LiteralPath $ApprovedBaselinePath)
if ($approvedAssignments.Count -eq 0) {
    throw "The approved assignment baseline is empty."
}
$requiredColumns = @("PrincipalId", "RoleName", "DirectoryScopeId")
$missingColumns = @(
    $requiredColumns |
    Where-Object { $_ -notin $approvedAssignments[0].PSObject.Properties.Name }
)
if ($missingColumns.Count -gt 0) {
    throw "The baseline is missing columns: $($missingColumns -join ', ')"
}

$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
$roleNameById = @{}
foreach ($role in $roleDefinitions) {
    $roleNameById[$role.Id] = $role.DisplayName
}

$activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop
$unexpectedAssignments = @(
    foreach ($assignment in $activeAssignments) {
        $roleName = $roleNameById[$assignment.RoleDefinitionId]
        $scope = if ($assignment.DirectoryScopeId) {
            $assignment.DirectoryScopeId
        }
        else {
            "/"
        }
        $approved = @(
            $approvedAssignments |
            Where-Object {
                $_.PrincipalId -eq $assignment.PrincipalId -and
                $_.RoleName -eq $roleName -and
                $_.DirectoryScopeId -eq $scope
            }
        ).Count -gt 0

        if (-not $approved) {
            [pscustomobject]@{
                AssignmentId    = $assignment.Id
                PrincipalId     = $assignment.PrincipalId
                RoleName        = $roleName
                DirectoryScopeId = $scope
            }
        }
    }
)

[pscustomobject]@{
    Control               = "Least-privileged administrative roles"
    UnexpectedAssignments = $unexpectedAssignments.Count
    Resolved              = $unexpectedAssignments.Count -eq 0
}

$unexpectedAssignments

Test-SecureM365ScoreAction `
    -Title "Use least privileged administrative roles" `
    -ControlName "RoleOverlap"
