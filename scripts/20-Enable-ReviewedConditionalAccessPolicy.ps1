#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [guid] $ConditionalAccessPolicyId,

    [switch] $UseDeviceCode,

    [ValidateRange(1, 12)]
    [int] $PropagationRetryCount = 6,

    [ValidateRange(0, 60)]
    [int] $PropagationRetryDelaySeconds = 10
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "SecureM365.Common.psm1") -Force -ErrorAction Stop

Connect-SecureM365Graph `
    -TenantId $TenantId `
    -AdditionalScopes "Policy.ReadWrite.ConditionalAccess" `
    -UseDeviceCode:$UseDeviceCode |
    Out-Null

function Get-ReviewedConditionalAccessPolicy {
    param([Parameter(Mandatory)][guid] $PolicyId)

    foreach ($attempt in 1..$PropagationRetryCount) {
        try {
            return Get-MgIdentityConditionalAccessPolicy `
                -ConditionalAccessPolicyId $PolicyId.Guid `
                -ErrorAction Stop
        }
        catch {
            $notFound =
                [string] $_.Exception.ResponseStatusCode -eq "NotFound" -or
                [string] $_.Exception.ResponseStatusCode -eq "404" -or
                $_.Exception.Message -match '(?i)\b404\b|ResourceNotFound|does not exist in the directory'
            if (-not $notFound -or $attempt -eq $PropagationRetryCount) {
                throw
            }
            Write-Warning "Conditional Access policy '$($PolicyId.Guid)' is not readable yet; waiting $PropagationRetryDelaySeconds seconds for propagation (attempt $attempt of $PropagationRetryCount)."
            if ($PropagationRetryDelaySeconds -gt 0) {
                Start-Sleep -Seconds $PropagationRetryDelaySeconds
            }
        }
    }
}

$policy = Get-ReviewedConditionalAccessPolicy -PolicyId $ConditionalAccessPolicyId

if ($policy.State -eq "enabled") {
    $policy | Select-Object Id, DisplayName, State
    return
}
if ($policy.State -ne "enabledForReportingButNotEnforced") {
    throw "Policy '$($policy.DisplayName)' is '$($policy.State)', not report-only. Review it before enabling."
}

if ($PSCmdlet.ShouldProcess($policy.DisplayName, "Enable Conditional Access policy")) {
    Update-MgIdentityConditionalAccessPolicy `
        -ConditionalAccessPolicyId $policy.Id `
        -BodyParameter @{ state = "enabled" } `
        -ErrorAction Stop
}

Get-ReviewedConditionalAccessPolicy -PolicyId ([guid] $policy.Id) |
    Select-Object Id, DisplayName, State
