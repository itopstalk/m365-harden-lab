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

$roleDefinitions = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName'
)
$roleNameById = @{}
foreach ($role in $roleDefinitions) {
    if (
        [string]::IsNullOrWhiteSpace([string] $role.id) -or
        [string]::IsNullOrWhiteSpace([string] $role.displayName) -or
        $roleNameById.ContainsKey([string] $role.id)
    ) {
        throw "Graph returned an incomplete or duplicate role definition."
    }
    $roleNameById[[string] $role.id] = [string] $role.displayName
}

$assignments = @(
    Get-SecureM365GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId'
)
$report = @(
    foreach ($assignment in $assignments) {
        if (
            [string]::IsNullOrWhiteSpace([string] $assignment.id) -or
            [string]::IsNullOrWhiteSpace([string] $assignment.principalId) -or
            [string]::IsNullOrWhiteSpace([string] $assignment.roleDefinitionId) -or
            [string]::IsNullOrWhiteSpace([string] $assignment.directoryScopeId)
        ) {
            throw "Graph returned an incomplete active role assignment."
        }
        $roleName = $roleNameById[[string] $assignment.roleDefinitionId]
        if ([string]::IsNullOrWhiteSpace($roleName)) {
            throw "Role assignment '$($assignment.id)' references unresolved role definition '$($assignment.roleDefinitionId)'."
        }

        $principalId = [uri]::EscapeDataString([string] $assignment.principalId)
        $principal = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$principalId" `
            -ErrorAction Stop
        if (
            [string] $principal.id -ne [string] $assignment.principalId -or
            [string]::IsNullOrWhiteSpace([string] $principal.'@odata.type') -or
            [string]::IsNullOrWhiteSpace([string] $principal.displayName)
        ) {
            throw "Role assignment '$($assignment.id)' references an incomplete or unresolved principal."
        }
        $principalType = [string] $principal.'@odata.type' -replace '^#microsoft\.graph\.', ''
        $principalName = @(
            [string] $principal.userPrincipalName
            [string] $principal.appId
            [string] $principal.displayName
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -First 1

        [pscustomobject]@{
            AssignmentId       = [string] $assignment.id
            PrincipalId        = [string] $assignment.principalId
            PrincipalType      = $principalType
            PrincipalName      = $principalName
            RoleDefinitionId   = [string] $assignment.roleDefinitionId
            RoleName           = $roleName
            DirectoryScopeId   = [string] $assignment.directoryScopeId
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
