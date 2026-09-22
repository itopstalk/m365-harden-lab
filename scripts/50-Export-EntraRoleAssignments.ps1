#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [string] $OutputPath = (Join-Path $PSScriptRoot "entra-active-role-assignments.csv"),
    [switch] $UseDeviceCode
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Directory.Read.All" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
$roleNameById = @{}
foreach ($role in $roleDefinitions) {
    $roleNameById[$role.Id] = $role.DisplayName
}

$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop
$report = @(
    foreach ($assignment in $assignments) {
        $scope = if ($assignment.DirectoryScopeId) {
            $assignment.DirectoryScopeId
        }
        else {
            "/"
        }

        [pscustomobject]@{
            AssignmentId    = $assignment.Id
            PrincipalId     = $assignment.PrincipalId
            RoleName        = $roleNameById[$assignment.RoleDefinitionId]
            DirectoryScopeId = $scope
        }
    }
)

$report |
    Sort-Object RoleName, PrincipalId |
    Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Force

[pscustomobject]@{
    TenantId        = $TenantId.Guid
    AssignmentCount = $report.Count
    OutputPath      = (Resolve-Path -LiteralPath $OutputPath).Path
}
