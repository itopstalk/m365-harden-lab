git clone https://github.com/itopstalk/m365-harden-lab.git

## Configure the lab using admin centers

The [browser procedure series](videos/README.md) provides a separate recording
guide for each configuration task, with admin-center navigation, exact lab
settings, execution order, and the handoff to script 99. It also documents
browser-only limitations and separates optional automation setup and cleanup
from the main hardening sequence.

## Standalone setup and assessment

`scripts\AA-AssessM365Status.ps1` combines scripts 00, 01, and 99, with the
required `SecureM365.Common.psm1` helpers embedded. Copy this one file to another
directory or machine; no other repository files are needed. The original scripts
remain available separately.

For assessment-only Graph consent, run from the `scripts` directory:

```powershell
.\AA-AssessM365Status.ps1 -UseGraphBrowserPkce -ConsentForAllScripts:$false
```

The script installs missing modules from PSGallery for the current user, prompts
for the tenant GUID if `-TenantId` is omitted, validates Graph and Teams access,
and runs the same ten checks as script 99. Teams validation is automatic and may
require its own sign-in; certificate authentication parameters are also supported.
A Teams access failure produces `UNKNOWN` for the Teams rows without suppressing
the remaining results. Tenant configuration is not changed.

PowerShell 7.2 or later is required for assessment. If launched in Windows
PowerShell or an older version, the script uses WinGet to install PowerShell 7
and stops; open `pwsh.exe` and rerun the same file. `-WhatIf` previews installation
without authenticating, reading tenant data, or writing a snapshot.

As in script 01, `ConsentForAllScripts` defaults to **true**, including the
high-privilege write scopes needed by the rest of the lab. Use the explicit false
value above when those scopes are not needed. As in script 99,
`SsprAllScopeConfirmed` defaults to **true**; use `-SsprAllScopeConfirmed:$false`
unless Password reset > Properties = All has been independently verified.

Snapshots default to `C:\SecureM365Snapshots`; use `-SnapshotDirectory` to change
the destination. `-PassThru` returns only the ten assessment objects, not module
inventories or connection summaries:

```powershell
$results = .\AA-AssessM365Status.ps1 -TenantId $TenantId `
    -UseGraphBrowserPkce -ConsentForAllScripts:$false `
    -SsprAllScopeConfirmed:$false -PassThru
$results | Where-Object Status -ne "IMPLEMENTED"
```

The same approved-exclusion parameters, evidence fields, coverage advisories,
and recognition limitations described in [tests.md](tests.md) apply.

## Standalone security configuration

`scripts\ZZ-ConfigureM365Status.ps1` combines scripts 04, 06, 10, 12, 14, 16,
18, 20, 30, 40, 42, and 44, with its required common-module helpers embedded.
It needs no other repository files. The original scripts remain unchanged.
Use Windows and PowerShell 7.2 or later. Like script AA, it installs any missing
prerequisite modules from PSGallery for the current user before connecting.
Approve installation when prompted; already-installed modules are reused without
being upgraded. You can also install the same prerequisites manually:

```powershell
Install-Module -Name Microsoft.Graph.Authentication,Microsoft.Graph.Identity.SignIns,`
    Microsoft.Graph.Identity.Governance,MicrosoftTeams,ExchangeOnlineManagement `
    -Scope CurrentUser -Repository PSGallery
```

With the prerequisites available, preview with authenticated read-only discovery,
then run the configuration. If modules are missing, `-WhatIf` previews their
installation and stops without installing anything or connecting to the tenant:

```powershell
.\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId -UseGraphBrowserPkce -WhatIf
.\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId -UseGraphBrowserPkce
```

The script creates or verifies two cloud-only emergency Global Administrators
and the certificate-based Teams automation application. It stages missing
CA001-CA005 policies, disables ordinary-user application consent while preserving
other grant assignments, and applies all three Global Teams meeting settings.
It then requires explicit emergency-access and MFA-readiness confirmation before
enabling report-only policies. `-Confirm:$false` does **not** bypass that separate
readiness confirmation, which defaults to **No**. Enrollment, tested emergency
sign-in, SSPR/password writeback, monitoring, appropriate licenses, and active administrative permissions
remain operator responsibilities. **Security Defaults must already be disabled**;
the script does not change it.

To split provisioning from enforcement without requiring another script:

```powershell
.\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId -ReportOnly
# After reviewing impact and testing the already-created emergency accounts:
$result = .\ZZ-ConfigureM365Status.ps1 -TenantId $TenantId `
    -EmergencyAccessReady -Confirm:$false -PassThru
```

`-ReportOnly` does not disable already-enabled policies. `-EmergencyAccessReady`
is an explicit readiness attestation and is rejected if any requested emergency
account still needs creation. Only verified matching users, application/certificate
setup, and policies are reused. Duplicates, disabled policies, partial identities,
or configuration differences stop the run; existing passwords are never reset,
certificates are not rotated, and unrelated policies are not changed. Temporary
CA003 legacy-authentication exceptions must be supplied explicitly; emergency
accounts are automatically excluded only from CA001, CA002, CA004, and CA005.

Policy comparisons ignore Graph OData response annotations, including
`authenticationStrength@odata.context`; these are metadata, not grant requirements.
Genuine setting differences still stop the run and show the expected and actual
normalized JSON without rewriting the existing policy.

New emergency passwords are saved and recovery-verified before creating users,
in `Documents\SecureM365\EmergencyAccessPasswords-<tenant>.json` by default.
The DPAPI artifact is decryptable only by the same Windows user on the same
computer. Keep a protected backup; use `-PasswordFilePath` for another destination
and approve `-OverwritePasswordFile` only after preserving any existing artifact.
Reused accounts produce no new password file. The Teams certificate has a
non-exportable RSA-3072 private key in `Cert:\CurrentUser\My`; reruns that reuse
the application require that certificate and private-key access.

**CA005 retains script 18's compatibility caveat:** its original `passwordChange`
plus MFA authentication-strength grant is preserved, not silently replaced with
another remediation model. Microsoft Graph currently documents `mfa` +
`passwordChange` or authentication strength + `riskRemediation` instead. A service
rejection stops the run. Successful readback does not prove live user remediation.
Failures report confirmed partial changes without rolling them back; review those
changes before retrying. `-PassThru` returns the final configuration report or
preview plan without passwords or private keys.

After a completed run, the displayed final results are saved as UTF-8 text to
`hardening-results.txt` in the current working directory, replacing the previous
file. The configuration plan and warnings are not included; `-WhatIf` does not
write this file.

New Conditional Access policies can briefly return HTTP 404/`ResourceNotFound`
when read immediately after creation. The script retries those reads, not the
creation request, using `-PropagationRetryCount` (default 6) and
`-PropagationRetryDelaySeconds` (default 10). If visibility still cannot be
confirmed, let the policy propagate and rerun the updated script as the same
Windows user on the same computer. Verified matching objects are reused; do not
delete the emergency accounts, application, certificate, or password artifact
to recover from a read-back delay.

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

Script 01 requests the complete delegated Microsoft Graph scope set used by
scripts 00-99 in one authorization transaction by default. This avoids
incremental Graph consent dialogs as later scripts add user, policy, role,
application, and authorization-policy write operations. The full set includes
high-privilege write scopes. Run subsequent scripts in the same PowerShell
process so they can reuse the validated process-scoped token. For read-only
connection validation, explicitly opt out with `-ConsentForAllScripts:$false`.

The Microsoft Graph Command Line Tools public client may show a first-run
delegated-consent page. Review the requested scopes and consent with the intended
lab account. Admin-restricted scopes can require administrator consent. On
success, script 01 verifies the tenant, delegated user, and granted scopes. A
matching process-scoped Graph context is reused; a wrong-tenant or
insufficient-scope context is never accepted. When full-workflow consent is
explicitly disabled, subsequent scripts automatically return to browser PKCE
when a context needs additional scopes. To force the same flow in the
administrator checker, use:

```powershell
.\05-Verify-Admin-Permissions.ps1 -TenantId $TenantId -UseGraphBrowserPkce -CheckOnly
```

Microsoft Graph consent cannot authorize other service endpoints. Delegated
Teams validation can still require a Teams sign-in; script 06 can replace later
Teams prompts with its dedicated certificate application. Exchange Online uses
its own modern-authentication connection. Neither boundary can be folded into a
Microsoft Graph consent dialog.

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
registration report can lag by up to 36 hours. In scripts 11, 13, and 99, an enabled
matching MFA configuration determines the MFA result; complete policy coverage
and registration readiness are separate advisories. The lag does not
affect scripts 62-69 because they do not use registration data. Run Microsoft's
impact report before enabling a setting; Microsoft recommends enabling only
after dependencies are remediated and the report shows zero impact.

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
connection—review the IDs before deciding whether to wait and retry script 07 or
revoke the partial setup.

Use [script 07](scripts/07-Test-TeamsCertificateApplication.ps1) to recheck the
existing application's certificate authentication and Global meeting-policy
read access without running setup again:

```powershell
.\07-Test-TeamsCertificateApplication.ps1 -TenantId $TenantId `
    -ApplicationId $TeamsApplicationId `
    -CertificateThumbprint $TeamsCertificateThumbprint
```

Run in PowerShell 7.2 or later with `MicrosoftTeams` installed and
`SecureM365.Common.psm1` beside script 07. It checks the local certificate's
private key and validity, connects explicitly as the application, verifies the
tenant, and reads exactly the Global policy. Only then does it return
`Status = PASSED` and `MeetingPolicyAccessVerified = True`; failures terminate
with an error. It needs no delegated Graph sign-in and changes no tenant settings.
This verifies read access, not policy configuration, exact role assignments, or
write authorization. The Teams connection remains available afterward.

On a separate test system, use the Windows user and machine where script 06
was run. Copying the scripts, application ID, and thumbprint does not copy its
non-exportable private key. If a different certificate has been deliberately
deployed and registered on the application, script 07 also accepts
`-CertificatePath` and an optional runtime `-CertificatePassword` SecureString
for a PFX outside the repository. No certificate export or import is performed.
After role or consent changes, allow propagation and retry in a new PowerShell
process.

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

Microsoft Graph does not expose the exact **None**, **Selected**, or **All**
setting shown under Entra ID > Password reset > Properties. Script 99 defaults
`SsprAllScopeConfirmed` to true based on the lab operator's confirmation, so the
normal command requires no SSPR flag. Per-user SSPR registration and capability
values are shown as advisory evidence and can lag by up to 36 hours.

For another tenant, or whenever **All** has not been verified, fail closed:

```powershell
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId `
    -SsprAllScopeConfirmed:$false
```

Script 99 displays `Number`, `Status`, `Recommendation`, and `Evidence` columns.
With `-PassThru`, each structured result includes the same `Evidence` value;
`Details` remains as a compatibility alias for existing consumers.
Every run also creates `C:\SecureM365Snapshots` when necessary and writes a
timestamped JSON file named
`<tenant>-m365-recommendation-status-<UTC timestamp>.json`. Use
`-SnapshotDirectory` to select another directory outside the repository.

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
07, and 99 validate meeting-policy reads.

For rotation in this lab, create a separately named application/certificate,
verify it with script 07, update scheduled commands to the new application ID
and thumbprint, then revoke the old identity. Script 06 deliberately refuses to
mutate an existing application, so it cannot accidentally replace a live
credential. Preview revocation and then remove cloud grants/objects; include the
switch only when the exact local certificate should also be deleted:

```powershell
.\08-Remove-TeamsCertificateApplication.ps1 -TenantId $TenantId `
    -ApplicationId $TeamsApplicationId -WhatIf

.\08-Remove-TeamsCertificateApplication.ps1 -TenantId $TenantId `
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

## MFA policy configuration checks

Scripts 10 and 12 create enabled Conditional Access policies for administrators
and all users respectively; they do not register authentication methods.
MFA enforcement does not wait for registration or a Secure Score refresh.
A sign-in to which the policy applies
must satisfy its grant, which can require registration or block access until a
usable method is available.

[Script 11](scripts/11-Test-AdminMfa.ps1),
[script 13](scripts/13-Test-AllUserMfa.ps1), and the two MFA recommendations in
[script 99](scripts/99-Test-M365RecommendationStatus.ps1) check whether a matching
MFA policy **exists and is enabled**. Administrator MFA matches policies directly
targeting directory roles or All users. All-user MFA matches policies targeting
All users. Detection uses the policy's actual grant and assignments, not its name.
Security Defaults is also accepted as an enabled MFA configuration.
This includes script 12's built-in MFA authentication strength, not only the
`builtInControls = mfa` grant.

| Evidence | Meaning |
| --- | --- |
| `PolicyFound` | A matching Conditional Access MFA policy was found, even if disabled or report-only. |
| `EnabledPolicyFound` | At least one matching policy has `state = enabled`. |
| `ProtectionConfigured` / `Resolved` | An enabled matching policy or enabled Security Defaults was found. |
| `CoverageVerified` | Separate advisory about broad coverage with only explicitly approved exclusions; null means the role inventory could not be evaluated. |
| `Policies` | Matching policy IDs, names, states, role targets, and user/group/role exclusions. |

An `IMPLEMENTED` MFA result is a **configuration-presence result**, not proof that
every administrator, user, resource, or sign-in is protected. Resource, client,
risk, and exclusion restrictions remain part of the coverage advisory. Disabled
and report-only policies do not pass. Neither does a grant allowing **MFA OR a
compliant device**, because MFA is then optional.

```powershell
.\11-Test-AdminMfa.ps1 -TenantId $TenantId
.\13-Test-AllUserMfa.ps1 -TenantId $TenantId
$results = .\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -PassThru
$results[0].PolicyConfiguration
$results[0].PolicyConfiguration.Policies | Format-List
$results[1].PolicyConfiguration.Policies | Format-List
```

Your approved emergency-account exclusions do not prevent policy detection.
To have the separate coverage advisory recognise those exclusions, supply the
same object IDs used with scripts 10 and 12:

```powershell
.\11-Test-AdminMfa.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds
.\13-Test-AllUserMfa.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds
```

Script 11's coverage advisory uses script 10's 16-role baseline. Script 99's
administrator coverage advisory checks currently assigned role templates, which
can include additional roles. The legacy-authentication recommendation in
script 99 still requires verified scopes and approved exclusions.

Registration counts, including emergency accounts, are advisory and can lag by
up to 36 hours. Missing registration or an unavailable registration report does
not negate an enabled policy. Script 13 assesses registration only for enabled
member accounts, reporting known non-capable users separately from missing data.
Scripts 11 and 13 no longer append a Secure Score result:
the old `ControlFound` meant the control appeared in a score snapshot, not that
an MFA policy was enabled. Script 99 continues to use live policy data, not
Secure Score. Its MFA `PolicyConfiguration` details are included in both
`-PassThru` output and JSON snapshots.

Copy the updated `SecureM365.Common.psm1` together with scripts 11, 13, and 99 when
running these checks on another system.

## Sign-in risk policy configuration checks

[Script 16](scripts/16-New-SignInRiskPolicy.ps1) creates CA004 enabled by default,
targeting All users except the supplied emergency accounts, all resources and
clients, and both medium and high **sign-in risk**. It requires MFA authentication
strength and every-time primary-and-secondary reauthentication. Use `-ReportOnly`
for staging. Risk-based Conditional Access requires Microsoft Entra ID P2.

[Script 17](scripts/17-Test-SignInRiskPolicy.ps1) and the sign-in risk recommendation
in script 99 share the same enabled-policy assessment. A matching policy must
target All users, cover **both medium and high sign-in risk**, require MFA, and
enable **every-time primary-and-secondary reauthentication**. Matching uses the
actual settings, not the policy name. Disabled and report-only matches have
`PolicyFound = True` but do not pass. Security Defaults alone is not a sign-in risk policy.

`Resolved = True` / `IMPLEMENTED` means an enabled matching policy was found.
Emergency-account exclusions do not prevent that result. `CoverageVerified` is a
separate advisory about all-resource/all-client coverage, additional conditions,
and approved exclusions. A presence result does not prove every account or
sign-in is protected. Policy IDs, names, states, risk levels, reauthentication
settings, and exclusions remain available for review.

```powershell
$risk = .\17-Test-SignInRiskPolicy.ps1 -TenantId $TenantId
$risk.Policies | Format-List

# Optional: approve reviewed exclusions for the coverage advisory.
.\17-Test-SignInRiskPolicy.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

$results = .\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -PassThru
$results[3].PolicyConfiguration
```

Neither check needs a risky sign-in event or completed registration reporting.
Script 17 now returns one policy-assessment object, without the separate Secure
Score result. Script 99 includes `PolicyConfiguration` in its pass-through
results and JSON snapshots. Read failures do not become successful assessments.

Users must still enroll usable MFA methods **before** a risky sign-in:
[Microsoft documents](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in)
that risk-based policies block initial MFA registration during risky sessions.
This runtime requirement is different from detecting the configured policy.

Copy scripts 17 and 99 together with the current `SecureM365.Common.psm1` to the
separate system. An existing CA004 policy does not need to be recreated.

## User-risk policy configuration checks

[Script 18](scripts/18-New-UserRiskPolicy.ps1) remains unchanged: it creates an
enabled high-user-risk policy with `passwordChange`, MFA authentication strength,
and every-time primary-and-secondary reauthentication, excluding the supplied
emergency accounts. This is not the modern adaptive `riskRemediation` workflow.

The [Graph grant-control reference](https://learn.microsoft.com/graph/api/resources/conditionalaccessgrantcontrols)
documents `mfa` plus `passwordChange` for legacy requests, and authentication
strength plus `riskRemediation` for modern requests. Detecting an existing
script-18-style policy is not a live validation of its password-reset or
self-remediation flow; verify those tenant prerequisites separately.

[Script 19](scripts/19-Test-UserRiskPolicy.ps1) and script 99's user-risk
recommendation now share an enabled-policy assessment. A matching policy must
target **All users**, include **high user risk**, require **MFA AND exactly one**
remediation control (`passwordChange` or `riskRemediation`), and require
**every-time primary-and-secondary reauthentication**. The modern control requires
MFA authentication strength in that policy. MFA alone, optional remediation,
both remediation controls together, and Security Defaults do not satisfy the check.

`PolicyFound` identifies a matching policy even when disabled or report-only;
only a matching **enabled** policy produces `Resolved = True` / `IMPLEMENTED`.
Emergency exclusions and narrower scope affect the separate `CoverageVerified`
advisory, not this presence result. The output includes the policy ID, name,
state, user-risk levels, remediation control, reauthentication, and exclusions.
It does not prove that every account is protected or that remediation has completed.

```powershell
$risk = .\19-Test-UserRiskPolicy.ps1 -TenantId $TenantId
$risk.Policies | Format-List
.\19-Test-UserRiskPolicy.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds

$results = .\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -PassThru
$results[4].PolicyConfiguration
```

Script 19 returns one assessment without a separate Secure Score result.
Neither check needs a risky-user event or a registration report. Both request
`Prefer: include-unknown-enum-members` when reading policies, including subsequent
pages, so Graph returns the newer `riskRemediation` value. Script 99 also saves
the structured policy evidence in its JSON snapshots.

Copy scripts 19 and 99 together with the current `SecureM365.Common.psm1` to the
separate system. These changes do not recreate, migrate, or enable tenant policies.

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
