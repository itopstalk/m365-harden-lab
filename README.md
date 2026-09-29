git clone https://github.com/itopstalk/m365-harden-lab.git

## Connect from the GitHub Copilot App

Run these commands from the `scripts` directory. If `-TenantId` is omitted,
script 01 prompts for the Microsoft Entra tenant GUID and validates it:

```powershell
.\00-Install-PowerShellTools.ps1
.\01-Test-TenantConnections.ps1 -UseGraphBrowserPkce
```

`-UseGraphBrowserPkce` is designed for Copilot's embedded/managed terminal when
the normal WAM browser flow or `-UseGraphDeviceCode` waits without displaying a
prompt. It opens the system browser and uses OAuth authorization code with PKCE,
a random state and nonce, and a short-lived localhost callback. Enter credentials
only on Microsoft's page. The scripts never accept a password parameter, read a
password from `credentials.txt`, or persist access/refresh tokens.

The Microsoft Graph Command Line Tools public client may show a first-run
delegated-consent page. Review the requested scopes and consent with the intended
lab account. Admin-restricted scopes can require administrator consent. On
success, script 01 verifies the tenant, delegated user, and granted scopes. A
matching process-scoped Graph context is reused; a wrong-tenant or
insufficient-scope context is never accepted. Subsequent scripts automatically
return to browser PKCE when that context needs additional scopes. To force the
same flow in the administrator checker, use:

```powershell
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -UseGraphBrowserPkce -CheckOnly
```

In Copilot mode, script 05 uses Graph to verify that the tenant has provisioned
Teams service plans and that the signed-in administrator has a provisioned,
enabled Teams plan. It then reports the meeting-policy check as `BLOCKED` instead
of starting Teams WAM or device authentication, which may wait without a visible
prompt. `Ready` remains false until `Get-CsTeamsMeetingPolicy` is actually read.
Run the check from a normal WAM-capable PowerShell host to validate delegated
Teams access. Certificate-based app authentication is a separate design that
must be reviewed independently.

If Security Defaults is enabled, script 05 never attempts Teams device
authentication from Copilot mode, even when both `-AttemptTeamsConnection` and
`-UseTeamsDeviceAuthentication` are supplied. Entra can reject the **MS Teams
PowerShell Cmdlets** app with error 530035 in that configuration. Do not weaken
or disable Security Defaults merely to make this check pass. In a suitable host,
the following explicitly opts into the normal Teams connection attempt after the
Graph licensing preflight:

```powershell
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -UseGraphBrowserPkce -AttemptTeamsConnection
```

Normal `Connect-MgGraph` interactive authentication and
`-UseGraphDeviceCode` remain available outside managed terminals. Browser PKCE
times out rather than waiting indefinitely. Local files named `credentials.txt`,
token files, and `.env` files are ignored by Git; do not put passwords or tokens
in repository files.

## Verify the lab administrator

After installing the tools with [script 00](scripts/00-Install-PowerShellTools.ps1)
and connecting with [script 01](scripts/01-Test-TenantConnections.ps1), run
[05-Verify-Admin-Permissions.ps1](scripts/05-Verify-Admin-Permissions.ps1) before
the configuration scripts. Set `$TenantId` to your lab tenant's GUID and run from
the `scripts` directory:

```powershell
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -CheckOnly
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -WhatIf
$report = .\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId
```

The checker lists role coverage, Graph scopes missing from the current token,
and missing modules. Normal execution offers interactive Graph consent and asks
for confirmation before each **permanent, active, tenant-wide** role assignment
to the signed-in account. `-CheckOnly` and `-WhatIf` do not assign roles or request
write scopes; initial discovery can still require consent to read scopes.

The dedicated baseline uses Conditional Access Administrator, User Administrator,
Privileged Role Administrator, Security Reader, and Teams Communications
Administrator where needed. Existing broader built-in roles and active
group-based assignments satisfy the relevant requirements without duplicate
grants. User Administrator also covers the SSPR Properties setting opened by
script 60; a separate Authentication Policy Administrator grant is not required
for that task.

- The account must already have active, tenant-wide **Privileged Role Administrator**
  or **Global Administrator** authority to assign roles. Otherwise the script
  stops and reports the gaps; it does not switch accounts or grant itself that
  authority. It never assigns Global Administrator.
- Activate existing PIM eligibility before running the checker to avoid
  unnecessary permanent grants. Scoped assignments do not satisfy tenant-wide
  requirements. Custom roles that could supply missing coverage need manual review.
- Graph consent is separate from directory roles and Teams authorization.
  A scope absent from the current token is not proof that consent is absent.
  Service probes test read access with the same Graph and Teams identity;
  no security policy changes or test-user creations are used to test write access.
- New assignments are read back but still require propagation and fresh tokens.
  Run `Disconnect-MgGraph` and `Disconnect-MicrosoftTeams`, then rerun the checker.
  `Ready` remains false in a run that creates assignments. Failures stop further
  assignments and do not roll back grants already made.
- This is a lab baseline, not a production privilege recommendation. Review and
  remove unneeded permanent assignments after the lab. Licensing, provisioning,
  Conditional Access, and individual script prerequisites remain separate checks.

The returned report includes `Ready`, `MissingRoles`, `RoleCoverage`,
`GraphPermissions`, `AccessChecks`, and `AssignmentsCreated`. Use
`Get-Help .\05-Verify-Admin-Permissions.ps1 -Full` for details and reference links.

## Teams meeting policy scope

[Script 40](scripts/40-Set-TeamsInvitedUsersLobbyPolicy.ps1),
[script 42](scripts/42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1), and
[script 44](scripts/44-Disable-TeamsAnonymousMeetingJoin.ps1) target **Global and
every returned meeting policy by default**, including predefined and unused policies.
[Script 99](scripts/99-Test-M365RecommendationStatus.ps1) audits **every returned
meeting policy** too. A compliant Global policy alone does not make the other
policies compliant.

**Microsoft-managed presets are read-only.** An update to a preset such as
`Tag:AllOn` can fail with `Tenant Admin can't modify first party documents`.
This is not a missing administrator role: Teams permits edits to Global and
tenant-created custom policies, not these presets. The scripts stop at that
rejection with the policy identity, recovery guidance, and the original error.
They do not skip the preset, retry the write, change assignments, or roll back
earlier updates.

Preview all three changes first:

```powershell
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId -WhatIf
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId -WhatIf
.\44-Disable-TeamsAnonymousMeetingJoin.ps1 -TenantId $TenantId -WhatIf
```

After reviewing the affected policies, run without `-WhatIf`:

```powershell
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId
.\44-Disable-TeamsAnonymousMeetingJoin.ps1 -TenantId $TenantId
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId
```

Each required update prompts for confirmation. Already-compliant policies are
not rewritten, and policy assignments are not changed. Updating a shared policy
affects users assigned to it; review the scope before applying this outside a lab.
Teams may need time to propagate changes. Running without parameters prompts for
the mandatory tenant ID and then targets all policies.

Use `-PolicyIdentity Global` to update only Global, or supply other identities to
target specific policies. `-AllPolicies` remains supported for compatibility but
is no longer required; it cannot be combined with `-PolicyIdentity`.
For example, to update the editable Global policy without targeting presets:

```powershell
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId -PolicyIdentity Global
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId -PolicyIdentity Global
.\44-Disable-TeamsAnonymousMeetingJoin.ps1 -TenantId $TenantId -PolicyIdentity Global
```

For tenant-created policies, replace `Global` with their identities. Do not
exclude every `Tag:` policy: custom policies use that prefix too.
If users or groups use a preset outside the baseline, review their assignments
and select a compliant Global or custom policy as appropriate. The scripts do
not perform that reassignment. See [Manage meeting policies](https://learn.microsoft.com/microsoftteams/meeting-policies-overview).

The scripts validate the complete target inventory before writing. `-WhatIf`
previews targets but cannot verify that Teams will permit an update. Other
failures, including ordinary access-denied errors, still stop execution and keep
their original diagnostics.

Because script 99 deliberately includes read-only and unused presets, its
all-policy checks can remain `NOT-CONFIGURED` after every editable policy is
updated. That does not establish that users are assigned to the listed presets.
Review assignments separately; read-only policies are not silently excluded or
reported as compliant.

Copy the updated [common module](scripts/SecureM365.Common.psm1) together with
the updated scripts if you run them from a separate folder.
