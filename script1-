## Install PowerShell Modules

$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.Governance"
    "MicrosoftTeams"
)

foreach ($moduleName in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module `
            -Name $moduleName `
            -Scope CurrentUser `
            -Repository PSGallery `
            -ErrorAction Stop
    }
}

$requiredModules |
    ForEach-Object {
        Get-Module -ListAvailable -Name $_ |
            Sort-Object Version -Descending |
            Select-Object -First 1 Name, Version, Path
    }
