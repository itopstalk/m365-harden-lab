#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = "Stop"

if (
    $PSVersionTable.PSEdition -ne "Core" -or
    $PSVersionTable.PSVersion -lt [version] "7.2"
) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw "Install App Installer from Microsoft, then install PowerShell 7.2 or later."
    }

    if ($PSCmdlet.ShouldProcess("this Windows client", "Install PowerShell 7 with WinGet")) {
        & winget.exe install --id Microsoft.PowerShell --source winget
        if ($LASTEXITCODE -ne 0) {
            throw "WinGet failed with exit code $LASTEXITCODE."
        }
    }

    Write-Warning "Close this terminal, open PowerShell 7 by running pwsh.exe, then run this script again."
    return
}

$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.Governance"
    "MicrosoftTeams"
)

foreach ($moduleName in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        if ($PSCmdlet.ShouldProcess($moduleName, "Install PowerShell module for the current user")) {
            Install-Module `
                -Name $moduleName `
                -Scope CurrentUser `
                -Repository PSGallery `
                -ErrorAction Stop
        }
    }
}

$requiredModules |
    ForEach-Object {
        Get-Module -ListAvailable -Name $_ |
            Sort-Object Version -Descending |
            Select-Object -First 1 Name, Version, Path
    }
