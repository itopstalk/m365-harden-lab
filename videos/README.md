# Microsoft 365 browser configuration procedures

These files are step-by-step recording guides for configuring the recommendations assessed by `99-Test-M365RecommendationStatus.ps1`. They use Microsoft admin centers, plus the browser-based Security info page for emergency-account enrollment, not PowerShell, Microsoft Graph Explorer, or browser developer tools. Each configuration task has its own file.

The scripts in `..\scripts` are the source of truth for names, assignments, and values. Microsoft Learn supplies the browser navigation. Navigation and labels were researched on October 5, 2026; **Entra ID** is labeled **Identity** in some portal layouts.

## Scope and browser-only limitations

The main sequence targets the **same 10 recommendation outcomes in script 99**, not a byte-for-byte reproduction of every script's side effects. Completing it should produce 10 `IMPLEMENTED` results when the prerequisites, approved exclusions, service access, and propagation requirements below are satisfied. This is an expected result, not a claim that a live tenant has been configured or assessed.

| Area | Browser procedure and limitation |
| --- | --- |
| Administrator MFA, all-user MFA, legacy authentication, sign-in risk, and the three Teams settings | Reproduce the scripts' policy names, scopes, grant choices, and settings. |
| User risk | The current documented portal workflow uses **Require risk remediation**. Script 18 writes `passwordChange`; script 99 explicitly accepts either `passwordChange` or `riskRemediation` with the required MFA and session controls. These are different remediation mechanisms, not identical policy payloads. Script 19 still checks specifically for `passwordChange`. |
| Emergency accounts | The browser creates the users and permanent Global Administrator assignments. It does **not** reproduce script 04's per-user `DisablePasswordExpiration` flag or its Windows DPAPI-encrypted password artifact. Those require an approved out-of-band process. An organization-wide password-expiration change is not an equivalent substitute. Script 99 does not assess either item. |
| Teams certificate application | The optional guide covers cloud registration, certificate upload, permissions, and roles. A browser cannot generate script 06's local, non-exportable private key. A correctly prepared local certificate is a prerequisite, not a browser step. |
| Application cleanup | The optional cleanup guide removes the cloud identity and permissions. It cannot remove a certificate from a Windows user's certificate store. |
| SSPR | Script 60 only opens a portal page. Its guide actually sets **Self service password reset enabled** to **All**. Script 99 records operator confirmation rather than reading that exact scope through Graph. |

Do not silently substitute stronger, narrower, or similarly named controls. For example, **Microsoft Admin Portals** is not the scripts' **All resources** assignment, a custom Teams meeting policy is not **Global**, and low-risk app consent is not disabled user consent.

## Prerequisites

- A Microsoft 365 worldwide-cloud lab tenant and approval to change its configuration.
- Microsoft Entra ID P1 entitlement for Conditional Access and SSPR, and P2 entitlement for the users covered by the risk policies. A provisioned Microsoft Teams service is also required. Use the appropriate licensing already available in the lab.
- Active administrator roles for the relevant portals. The guides identify them individually. The user-consent portal currently requires **Global Administrator**, even though script 30 can use **Privileged Role Administrator** with Graph.
- Registered, usable MFA methods for affected users before enforcement. Users must already be MFA-registered before a risk policy challenges them. Hybrid password remediation additionally requires a working, supported password-writeback configuration.
- Two usable cloud-only emergency accounts with phishing-resistant authentication, protected credentials, and a reviewed credential lifecycle. Creating accounts alone is not sufficient.
- A protected place outside this repository for recording the tenant GUID, emergency **user object IDs**, and optional application/certificate identifiers. Never put passwords, private keys, recovery material, or authentication tokens in the video files.

Pause recording for password entry, authentication-method registration, QR codes, and credential handling. Show placeholders rather than secrets in the finished recording.

## Recording and configuration order

Filenames retain the corresponding script numbers; they are **not** a dependency order. In particular, configure SSPR before user-risk remediation and do not run optional application cleanup as part of the hardening sequence.

| Order | Procedure | Admin tool |
| --- | --- | --- |
| 1, if role coverage is missing | [05 - Assign lab administrator roles](05-Assign-Lab-Administrator-Roles.md) | Microsoft Entra admin center |
| 2 | [04 - Create emergency access accounts](04-Create-Emergency-Access-Accounts.md) | Microsoft 365 and Microsoft Entra admin centers |
| 3 | [60 - Enable SSPR for all users](60-Enable-Sspr-For-All-Users.md) | Microsoft Entra admin center |
| 4, only if Security Defaults is enabled | [09 - Transition from Security Defaults](09-Transition-From-Security-Defaults.md) | Microsoft Entra admin center |
| 5 | [10 - Require MFA for administrators](10-Require-Mfa-For-Administrators.md) | Microsoft Entra admin center |
| 6 | [12 - Require MFA for all users](12-Require-Mfa-For-All-Users.md) | Microsoft Entra admin center |
| 7 | [14 - Block legacy authentication](14-Block-Legacy-Authentication.md) | Microsoft Entra admin center |
| 8 | [16 - Configure sign-in risk](16-Configure-Sign-In-Risk-Policy.md) | Microsoft Entra admin center |
| 9 | [18 - Configure user risk](18-Configure-User-Risk-Policy.md) | Microsoft Entra admin center |
| 10 | [30 - Disable user application consent](30-Disable-User-Application-Consent.md) | Microsoft Entra admin center |
| 11 | [40 - Set invited-user lobby bypass](40-Set-Teams-Invited-Users-Lobby.md) | Microsoft Teams admin center |
| 12 | [42 - Set organizer-only default presenters](42-Set-Teams-Organizer-Only-Presenters.md) | Microsoft Teams admin center |
| 13 | [44 - Disable anonymous meeting join](44-Disable-Teams-Anonymous-Meeting-Join.md) | Microsoft Teams admin center |

The five Conditional Access creation scripts enforce new policies **immediately by default**. Their procedures therefore finish with **Enable policy = On**. For a staged rollout, select **Report-only** instead and complete [20 - Enable a reviewed Conditional Access policy](20-Enable-Reviewed-Conditional-Access-Policy.md) for each staged policy before the final report. Report-only is not the finished configuration. Do not leave the tenant without replacement protection during a Security Defaults transition.

| Optional procedure | When to use it |
| --- | --- |
| [06 - Create the Teams certificate application](06-Create-Teams-Certificate-Application.md) | Only for certificate-authenticated Teams automation. Not needed to configure Teams in the browser or to run script 99 with delegated Teams sign-in. |
| [07 - Remove the Teams certificate application](07-Remove-Teams-Certificate-Application.md) | Only when retiring that automation identity. It does not undo the Teams meeting settings. Run after the identity is no longer needed. |
| [20 - Enable a reviewed Conditional Access policy](20-Enable-Reviewed-Conditional-Access-Policy.md) | Only for policies deliberately created in report-only mode. Already-enabled policies need no change. |

## Settings the final script expects

| Script 99 check | Required configuration |
| --- | --- |
| 1. MFA for administrative roles | Enabled broad MFA coverage. CA001 reproduces script 10's 16-role scope; CA002 also provides all-user coverage, including other administrative roles. |
| 2. MFA for all users | CA002: all users, all resources, built-in **Multifactor authentication** strength, only the approved emergency user exclusions. |
| 3. Block legacy authentication | CA003: all users, all resources, **Exchange ActiveSync clients** and **Other clients**, **Block access**. No exclusions by default. |
| 4. Sign-in risk | CA004: medium and high sign-in risk, all users/resources, MFA strength, every-time primary and secondary reauthentication. |
| 5. User risk | CA005: high user risk, all users/resources, MFA strength **AND** risk remediation, every-time primary and secondary reauthentication. See the script 18 difference above. |
| 6. No ordinary-user app consent | **Do not allow user consent**. Existing consent grants are not revoked. |
| 7. Invited-user lobby bypass | **Global** meeting policy: `AutoAdmittedUsers = InvitedUsers`. |
| 8. Default presenters | **Global** meeting policy: `DesignatedPresenterRoleMode = OrganizerOnlyUserOverride`. |
| 9. Anonymous meeting join | **Global** meeting policy: `AllowAnonymousUsersToJoinMeeting = false`. |
| 10. SSPR for all users | **Password reset > Properties > Self service password reset enabled = All**, genuinely confirmed by the operator. |

The risk policies require Security Defaults to be disabled. Keep all five policies free of extra device, platform, location, application-filter, authentication-flow, or other conditions not specified in their guides. The report does not infer broad coverage from arbitrary combinations of narrower policies.

## Handoff to the existing final script

No separate validation video is included. Keep using the repository's existing scripts for that purpose.

The browser work does not install PowerShell or modules, grant an application's delegated permissions, or establish Graph/Teams sessions. Prepare the reporting computer with script 00 if necessary. Use a normal PowerShell 7.2-or-later window with visible Microsoft sign-in prompts. The reporting identity needs the read permissions and active roles described in the [repository README](../README.md), including Teams meeting-policy access.

Replace the three placeholders below with the tenant GUID and the **user object GUIDs** recorded in procedure 04. These are not usernames, role-assignment IDs, or application IDs. Pass every deliberately approved exclusion to the report; it does not discover or approve emergency accounts by name.

```powershell
Set-Location 'C:\GitHub\m365-harden-lab\scripts'
$TenantId = [guid]'<tenant GUID>'
$EmergencyAccountIds = [guid[]]@(
    '<emergency-access-01 user object GUID>'
    '<emergency-access-02 user object GUID>'
)

.\01-Test-TenantConnections.ps1 -TenantId $TenantId -ConsentForAllScripts:$false -IncludeTeams
.\99-Test-M365RecommendationStatus.ps1 -TenantId $TenantId -ApprovedExcludedUserId $EmergencyAccountIds
```

Use the explicit `-TenantId` even when reusing a Graph connection. If you deliberately added temporary exceptions to CA003, include their approved user object IDs as well. Group or role exclusions require the corresponding `-ApprovedExcludedGroupId` or `-ApprovedExcludedRoleId` parameters; the default procedures do not create those exclusions.

Script 99 defaults `SsprAllScopeConfirmed` to true. That is valid only after completing procedure 60. If **All** has not actually been confirmed, supply `-SsprAllScopeConfirmed:$false`; the honest result is `UNKNOWN`.

Allow policy/role propagation and reconnect services as needed. Teams policy changes can take up to 24 hours. Authentication registration reporting can lag by up to 36 hours. The MFA results in scripts 11, 13, and 99 check for a matching enabled policy or Security Defaults; coverage, exclusions, and registration are separate advisories, not proof every sign-in is protected.

The sign-in risk results in scripts 17 and 99 also check for an enabled matching
policy, with coverage and exclusions reported separately. They require medium and
high sign-in risk, MFA, All users, and every-time primary-and-secondary
reauthentication; Security Defaults does not satisfy this check. Failed policy
reads can produce `UNKNOWN` in script 99. Unapproved exclusions still affect its
legacy-authentication and user-risk results; do not remove safety exclusions or
falsify SSPR confirmation to change a report result.

## Coverage of the remaining scripts

All configuration scripts have a linked procedure above. The following scripts intentionally have no separate browser procedure.

| Scripts or module | Reason |
| --- | --- |
| `00-Install-PowerShellTools.ps1` | Local reporting-tool installation, not a tenant security setting. |
| `01-Test-TenantConnections.ps1` | Service sign-in, delegated consent, and connection checks; retained in the reporting handoff. |
| `11-Test-AdminMfa.ps1`, `13-Test-AllUserMfa.ps1` | Read-only enabled MFA policy detection; coverage and registration are advisory. No Secure Score lookup. |
| `17-Test-SignInRiskPolicy.ps1` | Read-only enabled sign-in risk policy detection; coverage and exclusions are advisory. No Secure Score lookup. |
| `15-Test-BlockLegacyAuthentication.ps1`, `19-Test-UserRiskPolicy.ps1` | Read-only policy/registration/Secure Score checks. Script 19's legacy `passwordChange` test differs from script 99's accepted modern remediation path. |
| `31-Test-UserApplicationConsent.ps1` | Read-only consent and Secure Score checks. |
| `41-Test-TeamsInvitedUsersLobbyPolicy.ps1`, `43-Test-TeamsOrganizerOnlyPresenterPolicy.ps1`, `45-Test-TeamsAnonymousMeetingJoin.ps1` | Read-only checks of the Global meeting policy and Secure Score. |
| `61-Test-SsprAllUsers.ps1` | Read-only registration-report and Secure Score checks, not the exact portal scope. |
| `62-Test-BaselineAuthenticationAndApps.ps1`, `63-Test-BaselineSharePointAndOneDrive.ps1`, `64-Test-BaselineExchangeOnline.ps1`, `65-Test-BaselineMicrosoft365Apps.ps1`, `66-Test-BaselineTeamsAndCollaboration.ps1`, `69-Test-BaselineSecurityMode.ps1` | Read-only inventory of 20 additional Baseline Security Mode settings. These scripts do not configure those settings, and script 99 does not assess them. |
| `90-Test-AllSecureScoreControls.ps1` | Reads delayed Secure Score snapshots for 11 controls, including least-privileged administrative roles. It is not the final 10-check live report. |
| `99-Test-M365RecommendationStatus.ps1` | The existing final live report and local JSON snapshot writer. |
| `SecureM365.Common.psm1` | Shared authentication, configuration, and reporting helpers, not a standalone configuration task. |

Do not enable extra Baseline Security Mode settings merely to make this series look complete. In particular, script 62's `ENTRA-APP-002` expects limited low-risk consent, whereas script 30 and script 99 require **no** ordinary-user consent. Those exact expectations cannot both be satisfied. Similarly, CA001 uses ordinary MFA rather than the phishing-resistant strength tested by `AUTH-001`. The baseline inventory and Secure Score reports can therefore differ from script 99 even after the full browser sequence, just as they can after running the configuration scripts.
