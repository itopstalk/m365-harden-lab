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
Teams access, or use the dedicated certificate application described below.

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

## Validate Microsoft 365 Baseline Security Mode settings

Scripts 62-69 provide a read-only inventory of the 20 settings currently listed
on Microsoft's [Baseline Security Mode settings](https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide)
page. They validate supported native tenant controls, not the Baseline Security
Mode UI toggle, preview/draft state, or impact-report state. Microsoft documents
no API for those Baseline Security Mode surfaces.

Run the consolidated report from `scripts`:

```powershell
$report = .\69-Test-BaselineSecurityMode.ps1 -TenantId $TenantId -UseGraphBrowserPkce
$report
$report.Results | Format-Table SettingId, Workload, Status, Resolved, ActualValue -Wrap
$report.Results | Export-Csv .\baseline-security-mode.csv -NoTypeInformation
```

Exchange uses a separate modern interactive connection. Optionally direct the
prompt to a specific administrator:

```powershell
$report = .\69-Test-BaselineSecurityMode.ps1 -TenantId $TenantId `
    -UseGraphBrowserPkce `
    -ExchangeUserPrincipalName admin@contoso.onmicrosoft.com
```

Use `-SkipExchange` when Exchange Online is unavailable. `EXO-001` is then
returned as `UNKNOWN`; the report never turns a skipped or failed read into a
success. The workload scripts can also be run separately:

```powershell
.\62-Test-BaselineAuthenticationAndApps.ps1 -TenantId $TenantId -UseGraphBrowserPkce
.\63-Test-BaselineSharePointAndOneDrive.ps1
.\64-Test-BaselineExchangeOnline.ps1 -TenantId $TenantId
.\65-Test-BaselineMicrosoft365Apps.ps1
.\66-Test-BaselineTeamsAndCollaboration.ps1
```

Every result has stable `SettingId`, `Setting`, `Workload`, `Status`,
`Resolved`, `ActualValue`, `ExpectedValue`, `Evidence`, `SourceUrl`, and
`CheckedAt` fields. `Status` is `ENABLED`, `DISABLED`, or `UNKNOWN`.
`Resolved` is Boolean only for a determinable result and is null for `UNKNOWN`.
Authentication, authorization, service, empty/malformed response, and
wrong-tenant failures are explicit `UNKNOWN` evidence.

### Complete setting inventory

| ID | Setting | Workload | Validation |
|---|---|---|---|
| `AUTH-001` | Protect admin portal access with phishing-resistant MFA | Authentication / Entra | Automated: enabled Conditional Access policy, documented role coverage, Microsoft Admin Portals, phishing-resistant authentication strength |
| `AUTH-002` | Block legacy authentication flows | Authentication / Entra | Automated: enabled all-user/all-resource block for Exchange ActiveSync and other legacy clients |
| `ENTRA-APP-001` | Block addition of new password credentials to apps | Authentication / Entra | Automated: Graph `defaultAppManagementPolicy`, `passwordAddition` enabled for applications and service principals |
| `ENTRA-APP-002` | Restrict end-user consent to certified/single-tenant low-risk apps | Authentication / Entra | Automated: default user role assigned only `microsoft-user-default-low` |
| `APPS-001` | Block basic authentication | Microsoft 365 Apps | `UNKNOWN`: Baseline Security Mode / Office Cloud Policy Service / Trust Center UI only |
| `APPS-002` | Block insecure protocols for file opens | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service UI only |
| `APPS-003` | Block FrontPage RPC fallback for file opens | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service UI only |
| `SPO-001` | Block legacy browser authentication | SharePoint / OneDrive | `UNKNOWN`: RPS was permanently deprecated in October 2025, but Microsoft documents no supported live read property |
| `SPO-002` | Block legacy client authentication | SharePoint / OneDrive | `UNKNOWN`: `LegacyAuthProtocolsEnabled` is settable, but current `Get-SPOTenant` documentation does not confirm it as output |
| `SPO-003` | Do not allow new custom scripts | SharePoint / OneDrive | `UNKNOWN`: permanent tenant-wide behavior is BSM UI-only; per-site `DenyAddAndCustomizePages` is not equivalent |
| `SPO-004` | Disable Microsoft Store access for SharePoint | SharePoint / OneDrive | `UNKNOWN`: `DisableSharePointStoreAccess` is settable, but current `Get-SPOTenant` documentation does not confirm it as output |
| `EXO-001` | Disable organization-wide EWS access | Exchange Online | Automated: `Get-OrganizationConfig.EwsEnabled` must be explicitly false; null permits EWS |
| `FILES-001` | Protect ancient legacy formats and disallow editing | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service / impact report only |
| `FILES-002` | Protect old legacy formats and allow editing | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service / impact report only |
| `FILES-003` | Block ActiveX controls | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service / impact report only |
| `FILES-004` | Block OLE Graph and OrgChart objects | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service UI only |
| `FILES-005` | Block DDE server launches in Excel | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service UI only |
| `FILES-006` | Block Microsoft Publisher | Microsoft 365 Apps | `UNKNOWN`: Office Cloud Policy Service UI only; Publisher is removed from Microsoft 365 in October 2026 |
| `ROOMS-001` | Restrict Teams Rooms resource-account file access when not in use | Teams / collaboration | `UNKNOWN`: preview `Set-SPOTenant` input, may not exist, and is not documented as readable output |
| `ROOMS-002` | Allow only endpoint-managed compliant Teams Rooms devices | Teams / collaboration | `UNKNOWN`: requires correlated dynamic group, Conditional Access, Intune, and access-package evidence; no BSM API or stable BSM object identity |

The five automated rows are the complete set for which the linked Microsoft Learn
documentation provides a supported read surface and a sufficiently authoritative
mapping. The scripts intentionally do not treat secure Office defaults, a
settable-only SharePoint parameter, Secure Score, or a similarly named policy as
proof that a Baseline Security Mode setting is enabled.

### Modules, permissions, roles, and cloud scope

- Run script 00 to install `Microsoft.Graph.Authentication`,
  `Microsoft.Graph.Identity.SignIns`, and `ExchangeOnlineManagement` in addition
  to the repository's existing modules.
- Graph checks request delegated `Policy.Read.All`. Microsoft documents this as
  the least-privilege read permission for Conditional Access policies,
  authorization policy, and default app management policy. No new Graph scope
  was added because the repository already requests `Policy.Read.All`.
- Conditional Access reads support **Security Reader** or **Global Reader**;
  Conditional Access Administrator and Security Administrator also work.
  Reading `defaultAppManagementPolicy` requires **Global Reader** as the
  least-privileged supported delegated role. Script 05 now checks that role and
  probes the endpoint.
- Exchange read access requires Exchange Online RBAC **View-Only Organization
  Management**. Exchange Administrator is broader and is not automatically
  required by these read-only scripts. Script 05 verifies the module but cannot
  safely infer Exchange RBAC role-group membership through Graph.
- Microsoft 365 Apps manual checks require **Office Apps Administrator** to
  inspect/manage Office Cloud Policy Service. SharePoint manual checks require
  **SharePoint Administrator**. The room-device compliant-sign-in workflow
  requires Conditional Access Administrator and Exchange Online Administrator,
  plus Entra ID P1, Intune, and Entra ID Governance; Teams Rooms Pro does not
  include Entra ID Governance.
- These implementations target the Microsoft 365 worldwide cloud, matching the
  cited `o365-worldwide` documentation and the common Graph authenticator's
  explicit `Global` environment validation. Sovereign-cloud endpoint and feature
  availability are not inferred.

Conditional Access, role, consent, Exchange, and Baseline Security Mode changes
can require propagation and fresh service tokens. Microsoft documents up to
24 hours for relevant SharePoint legacy-auth changes. The authentication-method
registration report's existing 36-hour lag does not affect scripts 62-69 because
they do not use it. Run Microsoft's impact report before enabling a setting;
Microsoft recommends enabling only after dependencies are remediated and the
report shows zero impact.

Authoritative Microsoft sources are linked in each result and in comment-based
help. Key API references:

- [List Conditional Access policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies)
- [Get the default app management policy](https://learn.microsoft.com/en-us/graph/api/tenantappmanagementpolicy-get)
- [Configure user consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- [Control access to EWS](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-control-access-to-ews-in-exchange)
- [`Get-SPOTenant`](https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/get-spotenant)
- [Block noncompliant Teams Rooms devices](https://learn.microsoft.com/en-us/microsoftteams/rooms/block-non-compliant-teams-rooms-devices)

## Unattended Teams certificate authentication

Microsoft Teams PowerShell supports application authentication with an
application ID, tenant ID, and either a certificate in the current user's
certificate store or an `X509Certificate2` object. Microsoft's current support
page says all Teams cmdlets are supported except its explicit exclusion list;
`Get-CsTeamsMeetingPolicy` and `Set-CsTeamsMeetingPolicy` are not excluded.
For these `*-Cs` meeting-policy cmdlets, the dedicated application needs:

- Microsoft Graph **application** permission `Organization.Read.All`.
- The built-in **Teams Communications Administrator** directory role assigned
  directly to the application's service principal. It is narrower than Teams
  Administrator and its documented capabilities include managing meeting policies.
- No **Skype and Teams Tenant Admin API** permission. Microsoft explicitly says
  that permission is unnecessary and can cause application-authentication failures.

[Script 06](scripts/06-New-TeamsCertificateApplication.ps1) implements that
baseline. It creates a 3072-bit RSA/SHA-256 certificate in
`Cert:\CurrentUser\My` with `NonExportable` key policy and a 12-month lifetime by
default. Only the public certificate is uploaded to Entra; no client secret or
private key file is created. The stronger local key settings are this lab's
Windows hardening choice—Teams documentation does not prescribe a special key
size beyond using a certificate. The setup operator must interactively consent
to delegated `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, and
`RoleManagement.ReadWrite.Directory`, plus read-only `Organization.Read.All` for
explicit tenant validation; those permissions are used only to create and
authorize the dedicated application and are not granted to it.

Preview first, then create:

```powershell
$TenantId = [guid]'11111111-1111-4111-8111-111111111111'
.\06-New-TeamsCertificateApplication.ps1 -TenantId $TenantId -WhatIf
$teamsApp = .\06-New-TeamsCertificateApplication.ps1 -TenantId $TenantId
$TeamsApplicationId = [guid]$teamsApp.ApplicationId
$TeamsCertificateThumbprint = $teamsApp.CertificateThumbprint
```

The setup validates both the Graph context and `/organization` tenant ID, refuses
an existing application display name or local certificate subject, asks one
high-impact confirmation, and verifies `Get-CsTeamsMeetingPolicy -Identity Global`
through the resulting application connection. It never changes a colliding
identity. If setup fails after a write, its terminating error lists the object
IDs already created and an exact teardown command; it does not hide or silently
roll back partial state. Role and consent propagation can delay the final
connection—review the IDs before deciding whether to wait and retry script 01 or
revoke the partial setup.

Pass the same non-secret application ID and thumbprint to every new PowerShell
process. Script 01 verifies tenant and policy access; scripts 40-45 and 99 route
the same values to `Connect-SecureM365Teams`:

```powershell
.\01-Test-TenantConnections.ps1 -TenantId $TenantId -IncludeTeams `
    -TeamsApplicationId $TeamsApplicationId `
    -TeamsCertificateThumbprint $TeamsCertificateThumbprint

.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId `
    -TeamsApplicationId $TeamsApplicationId `
    -TeamsCertificateThumbprint $TeamsCertificateThumbprint

.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId `
    -TeamsApplicationId $TeamsApplicationId `
    -TeamsCertificateThumbprint $TeamsCertificateThumbprint
```

Certificate authentication removes the Teams sign-in prompt across processes,
but it does **not** make the private key portable. The default non-exportable key
is bound to the Windows user profile and machine where script 06 created it.
Tasks running as another user, on another machine, or in a non-interactive
service account cannot use that thumbprint. Deliberate deployment elsewhere must
use an approved certificate lifecycle: place a PFX outside the repository, pass
its path with `-TeamsCertificatePath`, and supply any password as a runtime
`SecureString` through `-TeamsCertificatePassword`. The module loads file-based
keys ephemerally and rejects PFX paths inside this repository. Never commit a
PFX, password, private key, token, or exported certificate bundle.

Delegated interactive and device authentication remain unchanged when no
application/certificate parameter is supplied. If any application-authentication
parameter is supplied, the module requires a nonempty application ID and exactly
one thumbprint or PFX path; invalid or incomplete application authentication
fails before `Connect-MicrosoftTeams` and never falls back to delegated sign-in.
The returned Teams tenant ID must exactly match `-TenantId`, and scripts 01, 05,
and 99 validate meeting-policy reads.

For rotation in this lab, create a separately named application/certificate,
verify it with script 01, update scheduled commands to the new application ID
and thumbprint, then revoke the old identity. Script 06 deliberately refuses to
mutate an existing application, so it cannot accidentally replace a live
credential. Preview revocation and then remove cloud grants/objects; include the
switch only when the exact local certificate should also be deleted:

```powershell
.\07-Remove-TeamsCertificateApplication.ps1 -TenantId $TenantId `
    -ApplicationId $TeamsApplicationId -WhatIf

.\07-Remove-TeamsCertificateApplication.ps1 -TenantId $TenantId `
    -ApplicationId $TeamsApplicationId `
    -CertificateThumbprint $TeamsCertificateThumbprint `
    -RemoveLocalCertificate
```

Troubleshooting:

- **Forbidden/Access Denied:** confirm `Organization.Read.All` has admin consent
  and Teams Communications Administrator is assigned directly to the service
  principal, then allow role/consent propagation and reconnect.
- **Certificate not found/private key unavailable:** run under the Windows user
  that created the certificate and inspect
  `Cert:\CurrentUser\My\<thumbprint>`. A public `.cer` file is insufficient.
- **Wrong tenant:** use the application's home tenant GUID. The scripts disconnect
  and stop rather than accepting a connection to another tenant.
- **PFX rejected:** keep it outside the repository, supply its password as a
  `SecureString`, and confirm the file contains an accessible private key.

Official Microsoft sources:

- [Application-based authentication in Teams PowerShell](https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication)
- [`Connect-MicrosoftTeams`](https://learn.microsoft.com/powershell/module/microsoftteams/connect-microsoftteams)
- [`Get-CsTeamsMeetingPolicy`](https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmeetingpolicy)
- [`Set-CsTeamsMeetingPolicy`](https://learn.microsoft.com/powershell/module/microsoftteams/set-csteamsmeetingpolicy)
- [Teams administrator roles and capabilities](https://learn.microsoft.com/microsoftteams/using-admin-roles)

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

## Emergency access account credentials

[Script 04](scripts/04-New-EmergencyAccessAccounts.ps1) generates a different
48-character cryptographically random password for every requested emergency
account. It does not prompt for, print, or accept passwords as command-line
arguments. Before the first tenant write, the script saves and verifies all
passwords in a JSON artifact protected by Windows user-scoped DPAPI. By default,
the tenant-specific file is created under the current user's
`Documents\SecureM365` directory. Use `-PasswordFilePath` to select another
protected location. An existing file is never replaced unless
`-OverwritePasswordFile` is explicitly supplied.

`-WhatIf` performs tenant discovery but does not generate passwords or create a
password file. After a successful run, copy the encrypted artifact to an approved
protected backup. It can be decrypted only by the same Windows user on the same
computer. Recover a credential without placing its plaintext on a command line:

```powershell
$artifact = Get-Content $PasswordFilePath -Raw | ConvertFrom-Json
$entry = $artifact.accounts |
    Where-Object userPrincipalName -eq 'emergency-access-01@contoso.onmicrosoft.com'
$securePassword = ConvertTo-SecureString $entry.encryptedPassword
$plainPassword = [System.Net.NetworkCredential]::new('', $securePassword).Password
# Use the password immediately. Then clear the variables and dispose the secure string.
$plainPassword = $null
$entry = $null
$artifact = $null
$securePassword.Dispose()
```

The artifact includes its schema version, DPAPI protection type, tenant ID,
creation time, and each account UPN. Treat the encrypted file as a sensitive
credential backup even though it contains no plaintext passwords.

## Conditional Access policy creation mode

Scripts 10, 12, 14, 16, and 18 create new Conditional Access policies as
**enabled and immediately enforced by default**. Before running them, validate
both emergency access accounts and confirm that affected administrators and users
are ready for MFA, modern authentication, and risk remediation as applicable.
These scripts never change an existing same-named policy; duplicate-name
protection stops creation for manual review.

Use `-ReportOnly` for staged creation:

```powershell
.\10-New-AdminMfaPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
.\12-New-AllUserMfaPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
.\14-New-BlockLegacyAuthenticationPolicy.ps1 -TenantId $TenantId -ReportOnly
.\16-New-SignInRiskPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
.\18-New-UserRiskPolicy.ps1 -TenantId $TenantId -EmergencyAccessAccountId $EmergencyAccountIds -ReportOnly
```

`-WhatIf` performs no policy write and identifies whether the requested creation
would be **enforced** (default) or **report-only**. Script 20 remains the explicit
path for enabling a previously staged, reviewed policy; the creation scripts do
not silently update or enable existing policies.

## Teams meeting policy scope

[Script 40](scripts/40-Set-TeamsInvitedUsersLobbyPolicy.ps1),
[script 42](scripts/42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1), and
[script 44](scripts/44-Disable-TeamsAnonymousMeetingJoin.ps1) intentionally
configure only the org-wide **Global** meeting policy. Validators 41, 43, and 45
and the Teams checks in [script 99](scripts/99-Test-M365RecommendationStatus.ps1)
assess that same exact policy. Each script fails rather than accepting a missing,
duplicate, or differently identified response.

Custom meeting policies and user/group policy assignments require a separate
review and are outside these lab checks. Microsoft-managed `Tag:*` presets and
tenant-created custom policies do not affect these results and are never modified
by scripts 40, 42, or 44.

Preview all three changes first:

```powershell
.\40-Set-TeamsInvitedUsersLobbyPolicy.ps1 -TenantId $TenantId -WhatIf
.\42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1 -TenantId $TenantId -WhatIf
.\44-Disable-TeamsAnonymousMeetingJoin.ps1 -TenantId $TenantId -WhatIf
```

After reviewing the Global policy changes, run without `-WhatIf`:

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
the mandatory tenant ID and still targets only Global. `-WhatIf` performs no
write but still reads Global for a precise preview and read-back evidence.

Review custom policies and assignments separately with
[Manage meeting policies](https://learn.microsoft.com/microsoftteams/meeting-policies-overview);
these scripts do not infer which custom policies are effective for users.

Copy the updated [common module](scripts/SecureM365.Common.psm1) together with
the updated scripts if you run them from a separate folder.
