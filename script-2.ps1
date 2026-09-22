$requiredCommands = @(
    "Connect-MgGraph"
    "Invoke-MgGraphRequest"
    "Get-MgIdentityConditionalAccessPolicy"
    "Get-MgRoleManagementDirectoryRoleAssignment"
    "Connect-MicrosoftTeams"
    "Get-CsTeamsMeetingPolicy"
    "Set-CsTeamsMeetingPolicy"
)

$missingCommands = @(
    $requiredCommands |
    Where-Object {
        -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
    }
)

if ($missingCommands.Count -gt 0) {
    throw "Required commands are missing: $($missingCommands -join ', ')"
}
