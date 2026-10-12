# Microsoft 365 tenant-hardening assessment: script 99

This document describes how to implement the ten security controls assessed by `scripts\99-Test-M365RecommendationStatus.ps1`, including the exact configurations its current implementation recognizes.

Use it as a candidate implementation guide and an assessor's interpretation guide. Administrators can configure the tenant through the admin centers, the repository's configuration scripts, or another supported administrative tool. Script 99 checks the resulting configuration, not which tool created it.

The recognition rules below come from script 99 and `scripts\SecureM365.Common.psm1`. Microsoft documentation is linked at the end for product behavior, supported configurations, and operational limitations. Recheck this document when either script changes, and distribute the scripts and common module from the same repository revision.

**A result of `IMPLEMENTED` means that the script's recognition rule was satisfied. It does not always prove complete tenant protection.** In particular:

- The MFA and risk-policy rows detect enabled matching policies; coverage and exclusions are separate advisories.
- The Teams rows inspect only the **Global (Org-wide default)** meeting policy.
- The SSPR row uses **operator confirmation**, which defaults to true. It does not independently read the tenant's **None / Selected / All** setting.

Recommended manual evidence in this document supplements the report. It does not change script 99's automated scoring rules. An assessor should agree on any additional coverage or operational requirements before the exercise starts.

## Control inventory

The numbers below are the `Number` values in script 99's output, in report order.

| Number | Security control | Configuration recognized by script 99 | Related configuration script |
| --- | --- | --- | --- |
| 1 | MFA for administrative roles | Enabled mandatory-MFA policy targeting directory roles or All users; alternatively, enabled Security Defaults | `10-New-AdminMfaPolicy.ps1` |
| 2 | MFA for all users | Enabled mandatory-MFA policy directly targeting All users; alternatively, enabled Security Defaults | `12-New-AllUserMfaPolicy.ps1` |
| 3 | Block legacy authentication | Enabled, sufficiently broad all-user block covering both legacy client types, with only approved exclusions; alternatively, enabled Security Defaults | `14-New-BlockLegacyAuthenticationPolicy.ps1` |
| 4 | Sign-in risk | Enabled All-users policy covering Medium and High sign-in risk, mandatory MFA, and every-time primary-and-secondary reauthentication | `16-New-SignInRiskPolicy.ps1` |
| 5 | User risk | Enabled All-users policy covering High user risk, MFA AND exactly one recognized remediation control, and every-time primary-and-secondary reauthentication | `18-New-UserRiskPolicy.ps1`; see its compatibility caveat below |
| 6 | Disable ordinary-user application consent | No recognized self-consent assignment in the default user role's permission-grant policy collection | `30-Disable-UserApplicationConsent.ps1` |
| 7 | Invited-user Teams lobby bypass | Global meeting policy: `AutoAdmittedUsers = InvitedUsers` | `40-Set-TeamsInvitedUsersLobbyPolicy.ps1` |
| 8 | Organizer-only default Teams presenters | Global meeting policy: `DesignatedPresenterRoleMode = OrganizerOnlyUserOverride` | `42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1` |
| 9 | Disable anonymous Teams meeting join | Global meeting policy: Boolean `AllowAnonymousUsersToJoinMeeting = false` | `44-Disable-TeamsAnonymousMeetingJoin.ps1` |
| 10 | SSPR for all users | Operator confirmation that Password reset > Properties is set to All | `60-Open-SsprSettings.ps1` opens the page only |

There is no separate row for script 20. `20-Enable-ReviewedConditionalAccessPolicy.ps1` promotes an existing report-only policy to enabled; its effect is assessed under the relevant row above. Script 99 is not a general validator for every Conditional Access policy.

## Interpreting results

| Status | Meaning for this assessment |
| --- | --- |
| `IMPLEMENTED` | The row's recognition rule was satisfied. Read its evidence and any limitations before awarding broader coverage or operational credit. |
| `NOT-CONFIGURED` | The readable configuration did not satisfy that rule. This can include a real policy that is report-only, differently scoped, or configured with a different control. |
| `UNKNOWN` | The script could not verify the requirement, or the legacy-authentication check found block policies whose required coverage it could not establish. It is not a pass and is not proof that the control is absent. |

Script 99 reads live Microsoft Graph v1.0 and Teams configuration, not Microsoft Secure Score. Secure Score points, a `ControlFound` result from another diagnostic, or a policy with a convincing name are not substitutes for these rules.

The script is read-only with respect to tenant configuration, but writes a local JSON snapshot. It does not enable policies, register authentication methods, revoke consent, or change Teams or SSPR settings.

## Preparation and safe implementation

### Tenant, licensing, access, and tooling

- Use an authorized test tenant in the Microsoft 365 **worldwide cloud**. The current report rejects other Graph cloud environments.
- Use PowerShell **7.2 or later**. Script 99 requires `Microsoft.Graph.Authentication` and `MicrosoftTeams`; the configuration scripts have additional module requirements. Script 00 installs the repository's tools.
- Conditional Access requires appropriate Microsoft Entra ID P1 or P2 licensing; the two risk-based controls require **P2**. Teams must be provisioned and accessible. SSPR users need licensing appropriate to cloud reset or hybrid writeback. Script 99 is not a license-compliance checker.
- Verify both Microsoft Graph and Teams access using script 01 with `-IncludeTeams`. A successful Graph connection or Graph consent does not grant Teams permissions.
- Use active administrative roles appropriate to the operation. Conditional Access Administrator supports CA configuration; Teams Communications Administrator supports meeting-policy administration. Current Microsoft guidance requires Global Administrator for the portal user-consent change, while its Graph path supports Privileged Role Administrator. SSPR administration also needs an appropriate role, such as Authentication Policy Administrator. Use the least privilege supported by the chosen operation.
- If a role is managed through PIM, activate it and allow propagation before obtaining fresh service connections. Missing read permissions must be corrected rather than treated as evidence that a control is missing.

The common Graph connector requests the repository's read-only scope profile: `AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `SecurityEvents.Read.All`, and `User.Read.All`. This is the shared profile, not a claim that every scope is individually necessary for every report row. Script 01 normally requests broader write scopes for the whole lab; use `-ConsentForAllScripts:$false` for read-only assessment setup.

### Avoid lockout

Establish and test emergency access before changing authentication policies. Enroll administrators and users in suitable authentication methods before enforcing controls they must satisfy. Review service accounts, legacy clients, and hybrid password-reset dependencies.

Scripts 10, 12, 14, 16, and 18 create **enabled policies by default**. Use their `-WhatIf` and `-ReportOnly` options for a staged deployment where appropriate. Report-only is useful for reviewing impact, but does not earn an enabled-policy result. Once reviewed, enable the policy in the portal or use script 20. Script 20 assumes a human has reviewed the policy; it does not review sign-in logs or validate lockout safety.

Scripts 10, 12, 16, and 18 require two through ten emergency-account object IDs. That is a creation-script safeguard, not a separate condition in script 99's policy-presence checks. Existing same-name policies cause the creation helper to stop rather than create duplicates; inspect and manage the existing policy instead.

Do not remove necessary protections, broaden unsafe access, or approve unjustified exclusions just to produce green rows. A valid but differently implemented security control may require a documented manual assessment exception.

## Shared Conditional Access recognition rules

These rules explain the difference between a configuration that passes the report and a configuration that protects the intended population.

### Policy state, identity, and assignment

Only `state = enabled` counts as an enabled CA policy. `disabled` and `enabledForReportingButNotEnforced` do not.

For rows 1, 2, 4, and 5, a policy can be present but not enabled:

| Evidence field | Interpretation |
| --- | --- |
| `PolicyFound` | At least one policy matches the row's assignments and required controls, even if disabled or report-only. |
| `EnabledPolicyFound` | At least one matching policy is enabled. |
| `ProtectionConfigured` / `Resolved` | The shared assessment's configuration result; these are nested inside `PolicyConfiguration` in script 99. |
| `CoverageVerified` | A separate broad-scope advisory, not the pass criterion for these four rows. False means broad coverage was not established; null means it could not be evaluated. |
| `Policies` | Matching policy summaries, including identity, state, assignments, and exclusions; risk rows include additional risk/session evidence. |

Do not mark a row as passed solely because `PolicyFound` is true. A matching policy without usable ID/name data or with an unrecognized state causes the assessment to fail verification and script 99 to report `UNKNOWN`.

Policy display names do not have to be `CA001` through `CA005`. A manually created, renamed, or Microsoft-managed CA policy can count if its returned configuration satisfies the relevant rule.

**All users means a direct CA assignment:** `conditions.users.includeUsers` contains `All`. A group containing every current user, a dynamic group, or a complete-looking list of individual users is not treated as All users. Script 99 does not calculate the union of such memberships.

Each risk-policy row requires its conditions, grants, and session settings in the **same policy**. Likewise, the legacy-authentication row requires one qualifying block policy; it does not combine separate partial policies into one qualifying policy.

### Security Defaults alternative

An enabled Security Defaults policy satisfies rows **1, 2, and 3**. It does not satisfy either risk-policy row.

Security Defaults uses Microsoft's own protection and prompting rules; a pass through this alternative is not a claim that its behavior is identical to a custom always-applicable all-user MFA policy. A CA policy need not exist for these rows to pass through Security Defaults.

Security Defaults is not a configurable exception mechanism and is not a way to complete all ten controls without Conditional Access. Microsoft requires disabling it when replacing it with CA policies. Plan an authorized transition with replacement protections ready; do not disable it merely to work around an assessment sign-in problem.

### What counts as mandatory MFA

The common evaluator recognizes either the built-in `mfa` grant or an authentication strength that it can identify as requiring MFA.

| Recognized authentication strength | Built-in ID |
| --- | --- |
| Multifactor authentication | `00000000-0000-0000-0000-000000000002` |
| Passwordless MFA | `00000000-0000-0000-0000-000000000003` |
| Phishing-resistant MFA | `00000000-0000-0000-0000-000000000004` |

It also accepts a returned authentication-strength object whose `requirementsSatisfied` is `mfa`. A custom strength returned only as an unfamiliar ID, without that evidence, is not recognized just because its display name contains "MFA." The evaluator does not independently expand and analyze every custom strength's allowed authentication combinations.

The grant must make MFA mandatory:

- `AND` can require MFA alongside another grant. The separate user-risk remediation rules still apply to row 5.
- `OR` is accepted only when there is no non-MFA alternative. Requiring the single MFA control through an OR grant is valid.
- **MFA OR compliant device**, **MFA OR hybrid joined device**, or an OR alternative involving terms of use or a custom authentication factor does not qualify.
- A grant containing `block` does not qualify as an MFA grant.
- A missing or unrecognized grant operator does not qualify.

Enabling authentication methods, running an MFA registration campaign, registering users, setting legacy per-user MFA, or relying on Microsoft's separate mandatory administrator MFA rollout is not independently detected as a passing CA configuration. The report needs a recognized CA policy or the Security Defaults alternative.

### Exclusions and their approval

Use the following script 99 parameters only for exclusions actually approved for the exercise:

| Parameter | Required identifier |
| --- | --- |
| `-ApprovedExcludedUserId` | User object GUIDs, including any approved emergency or temporary-exception accounts |
| `-ApprovedExcludedGroupId` | Group object GUIDs |
| `-ApprovedExcludedRoleId` | Directory role **template** GUIDs, not role-assignment IDs |

These parameters accept arrays. They do not modify CA policies, exempt a user themselves, approve anything by account name, or discover emergency accounts automatically.

| A matching policy has an unapproved exclusion | Effect |
| --- | --- |
| Rows 1 and 2: administrator/all-user MFA | Enabled-policy recognition can still pass; coverage/exclusion evidence reports the limitation. |
| Rows 4 and 5: sign-in/user risk | Enabled-policy recognition can still pass; coverage/exclusion evidence reports the limitation. |
| Row 3: legacy authentication | That policy does not qualify for the strict coverage check. If no other qualifying policy or Security Defaults exists, an enabled block policy normally leads to `UNKNOWN`. |

Approval checks compare identifiers. They do not validate the business justification, expire a temporary exception, or prove that an approved excluded group has a small or safe membership. Keep an independently approved exception register.

Script 99 has no approval parameter for the CA `excludeGuestsOrExternalUsers` object. Such an exclusion prevents broad-scope verification; for row 3 it prevents that policy from qualifying. Excluding particular guest object IDs is different and can be evaluated through the user-ID approval list.

Approved exclusions are not removed from the MFA or SSPR registration advisory population.

### Broad scope: advisory for MFA/risk, mandatory for legacy blocking

The shared broad-scope helper requires:

- An enabled policy and only approved user/group/role exclusions, without a guest/external-user exclusion object.
- `includeApplications` containing `All`, with no application exclusions.
- No application filter, user-action target, or authentication-context target.
- `clientAppTypes` containing `all`, except that the legacy check also accepts both `exchangeActiveSync` and `other`.
- No additional populated restricting conditions beyond the row's intended risk condition. An explicit All-platforms selection or All-locations selection is accepted if it has no exclusions.

These tests apply to each candidate policy. One narrow or unapproved policy does not cancel coverage supplied by another qualifying policy. The overall coverage advisory can therefore be true while the evidence also lists other matching policies with restrictions or unapproved exclusions.

For ordinary MFA, a risk condition prevents broad-scope verification even though the policy can still be detected. For sign-in risk, an additional user-risk condition prevents broad-scope verification; for user risk, an additional sign-in-risk condition does the same. Trusted-location exclusions, selected platforms, device filters, and browser-only targeting are examples of restrictions that prevent it.

For administrator coverage, a qualifying All-users policy is sufficient. Otherwise, the evaluator attempts to resolve active role assignments to built-in role templates and compares them with the roles covered by broad enabled policies. Missing/unresolvable role information is advisory. This is not an audit of every eligible PIM assignment, administrative permission, custom role, or future role assignment.

**Even `CoverageVerified = true` is not an end-to-end access test.** Approved exclusions remain excluded, group membership is not exhaustively assessed, and the report does not simulate policy interactions or actual sign-ins.

## Control 1: MFA for administrative roles

**Report recommendation:** Ensure multifactor authentication is enabled for all users in administrative roles

### Implement

In **Microsoft Entra admin center > Entra ID > Conditional Access**, create an enabled policy with mandatory MFA. Target the intended **Directory roles**, or use an applicable **All users** policy. For broad protection, include All resources, cover all client types, and avoid narrowing conditions apart from approved emergency exclusions.

Script 10 creates a role-targeted policy using the built-in MFA grant. Its selected role set is:

| Role | Role |
| --- | --- |
| Global Administrator | Application Administrator |
| Authentication Administrator | Authentication Policy Administrator |
| Billing Administrator | Cloud Application Administrator |
| Conditional Access Administrator | Exchange Administrator |
| Helpdesk Administrator | Identity Governance Administrator |
| Password Administrator | Privileged Authentication Administrator |
| Privileged Role Administrator | Security Administrator |
| SharePoint Administrator | User Administrator |

### Exact recognition and exceptions

With Security Defaults disabled, **one enabled mandatory-MFA policy that directly includes at least one directory role or All users is sufficient for this row's status**. The status does not require the complete role set above, or every role currently used in the tenant, to be covered.

A group called "Administrators," individual administrator accounts, or a role assignment outside the policy's `includeRoles` collection does not establish role-based targeting for this check. It can be a legitimate alternative deployment, but is not detected as this rule's role assignment.

An All-users MFA policy can satisfy both rows 1 and 2; two separate policies are not required by script 99. Conversely, a policy covering only one role can satisfy row 1 while leaving other administrators unprotected. Check `CoverageVerified`, `MissingAdministrativeRoles`, and the actual policy scope before awarding full administrator-coverage credit.

The registration advisory considers enabled users identified through direct active role assignments or the registration report's administrator flag. Missing data or administrators not reported MFA-capable does not overturn a verified policy result. It remains important operational evidence, especially before enforcement.

## Control 2: MFA for all users

**Report recommendation:** Ensure multifactor authentication is enabled for all users

### Implement

Create an enabled policy with **Users > Include > All users** and mandatory MFA. For the intended tenant-wide hardening outcome, select **All resources**, cover all clients, and document any emergency exclusions.

Script 12 uses the built-in **Multifactor authentication** authentication strength rather than the older built-in MFA grant. Both forms are recognized when MFA is mandatory.

### Exact recognition and exceptions

The required assignment is `includeUsers` containing `All`. A directory-role-only policy, an all-staff group, a dynamic membership rule, or a list of all current users does not substitute for that assignment.

Exclusions and narrower resource/client/risk conditions are advisory rather than status gates. **An All-users policy that requires MFA only for a specific app or for risky sign-ins can therefore produce `IMPLEMENTED` for this row.** It can also satisfy row 1. This is a limitation of policy-presence scoring, not proof of general all-user MFA coverage. For a genuine all-user baseline, implement and review the broad policy described above rather than relying only on a risk-triggered policy.

An enabled Security Defaults policy also satisfies this row.

Registration readiness is advisory for enabled **member** accounts; disabled accounts and guests are not part of this all-member registration check. Missing report rows are distinguished from accounts reported not MFA-capable. Registration data can lag, and its absence does not mean that an already enabled policy waits for first sign-in before becoming applicable.

## Control 3: Block legacy authentication

**Report recommendation:** Enable Conditional Access policies to block legacy authentication

### Implement

Create one enabled Conditional Access policy with:

| Setting | Required lab configuration |
| --- | --- |
| Users | Include All users |
| Target resources | Include All resources; exclude none |
| Client apps | Exchange ActiveSync clients **and** Other clients |
| Grant | Block access |
| Exclusions | None, or only explicitly approved user/group/role exclusions |
| Other conditions | No narrowing restrictions; see the broad-scope rules |

The returned client values are `exchangeActiveSync` and `other`; the grant includes `block`. Script 14 creates this configuration and accepts optional temporary-exception user IDs.

### Exact recognition and exceptions

Unlike the MFA and risk rows, this row applies the **strict broad-scope helper** to determine whether a policy qualifies. Approval of any temporary or emergency exclusions must be supplied when running script 99.

The helper also accepts a block policy with `clientAppTypes = all`. **Do not choose All client apps just to pass:** an All-users/All-resources block can deny modern authentication too. The two legacy client types are the intended configuration.

Two separate policies that each block only one legacy client type are not combined. Neither is a set of narrower app, location, or group policies, even if an administrator can demonstrate equivalent combined coverage.

An enabled Security Defaults policy is accepted instead of a CA block policy. Disabling basic authentication in Exchange or another service, by itself, is not inspected as an alternative.

If no qualifying policy exists but any enabled CA block policy is found, the result is `UNKNOWN` because required coverage was not verified. If Security Defaults is disabled and no enabled block policy is found, the result is `NOT-CONFIGURED`. Thus a report-only block policy alone does not pass.

## Control 4: Sign-in risk

**Report recommendation:** Enable Microsoft Entra ID Identity Protection sign-in risk policies

### Implement

In Conditional Access, configure the following in **one enabled policy**:

| Field or setting | Required value |
| --- | --- |
| Users | Include All users |
| Sign-in risk | Include both Medium and High |
| Grant | Mandatory MFA, using a recognized MFA grant or authentication strength |
| Sign-in frequency enabled | Boolean `true` |
| Sign-in frequency interval | `everyTime` |
| Sign-in frequency authentication type | `primaryAndSecondaryAuthentication` |

The portal path is **Conditions > Sign-in risk**, then **Grant > Require authentication strength > Multifactor authentication**, and **Session > Sign-in frequency > Every time**. Include All resources and all clients for the intended broad configuration. Script 16 creates this form.

### Exact recognition and exceptions

Both Medium and High must be included in the same policy. Adding Low does not stop it matching, but a High-only policy or separate Medium-only and High-only policies do not satisfy the rule.

An enabled policy targeting only a passwordless-users group does not pass this All-users check, even if that is a valid policy for that population. A sign-in-risk block policy does not substitute for the expected MFA remediation behavior.

A periodic sign-in frequency, secondary-authentication-only frequency, disabled/missing frequency, or non-Boolean enabled value does not match. Merely naming the policy "Sign-in risk" is insufficient.

Unapproved emergency exclusions, browser-only targeting, application exclusions, restricting location conditions, or an additional user-risk condition do not prevent an otherwise matching policy from being detected. They do prevent that policy from satisfying broad-scope verification. Approved emergency exclusions alone do not; other qualifying policies can also establish the overall coverage advisory.

Security Defaults is not a substitute. No risky sign-in needs to have occurred, and the script does not inspect risk events or completed MFA challenges. Risk-based MFA can block registration during a risky session, so enroll users before enforcement rather than treating an advisory-only registration result as proof that users can recover.

## Control 5: User risk

**Report recommendation:** Enable Microsoft Entra ID Identity Protection user risk policies

### Implement

For a new portal-based deployment, use Microsoft's **Require risk remediation** configuration. In Conditional Access, target **All users**, select **All resources**, configure **User risk > High**, and select **Grant > Require risk remediation** with an MFA authentication strength. The portal applies the required every-time sign-in frequency. Review and enable the policy.

The checker requires these settings together in one policy:

| Field or setting | Required value |
| --- | --- |
| Policy state | `enabled` |
| Users | `includeUsers` contains `All` |
| User risk | `userRiskLevels` contains `high` |
| Grant operator | `AND` |
| MFA | Required through a recognized grant/strength |
| Remediation | Exactly one `passwordChange` or `riskRemediation` entry |
| Sign-in frequency | Boolean enabled, `everyTime`, `primaryAndSecondaryAuthentication` |

### Recognized remediation variants

| Variant | Built-in grant controls | Authentication strength | Recognition |
| --- | --- | --- | --- |
| Modern adaptive remediation | `riskRemediation` | An MFA strength is required | Accepted; do not also include the built-in `mfa` grant |
| Documented legacy password change | `mfa`, `passwordChange` | Not required for this form | Accepted with `AND` |
| Existing script 18 form | `passwordChange` | Recognized MFA strength | Accepted for compatibility with the current creator |

**Important script 18 caveat:** script 18 still creates `passwordChange` plus an MFA authentication strength. Its policy name says "remediation," but its grant is not `riskRemediation`. Current Graph documentation describes `mfa + passwordChange` for the legacy request form and `authenticationStrength + riskRemediation` for the modern form. Recognition of the existing script 18 form does not certify that its live password-reset/remediation flow works, or make it equivalent to adaptive remediation. Do not treat this guide as an instruction to recreate or migrate an existing policy without review.

Script 99 requests `Prefer: include-unknown-enum-members` when reading CA policies, including paginated results, so Graph can return the modern `riskRemediation` value. An old checker or a separate API client that omits this header can instead see `unknownFutureValue` and fail to recognize it.

### Exceptions and non-equivalent configurations

The following do not satisfy the recognition rule: Medium-only user risk; sign-in risk instead of user risk; group-only targeting; OR between MFA and remediation; MFA without remediation; remediation without MFA; both remediation controls together; modern remediation without an MFA strength; modern remediation combined with the built-in `mfa` grant; a block grant; or missing/incorrect every-time reauthentication.

High plus additional user-risk levels still matches. Exclusions and resource/client/other-condition restrictions remain coverage advisories for this row rather than status gates.

That permissive detection is **not** permission to deploy an unsupported combination. Microsoft's remediation guidance requires all applications without application exclusions and restricts additional conditions. Use a supported full-scope configuration rather than inferring deployment validity from the checker's acceptance of a returned policy.

Modern remediation adapts to password-based and passwordless threats. Password-change-only remediation is not equivalent in all scenarios. Microsoft also documents that modern Require risk remediation is not supported for external and guest users. Any guest handling or exception must be assessed separately; a detected All-users policy does not prove those users can self-remediate.

For password-change scenarios, verify usable MFA methods, SSPR readiness, and password writeback where applicable. The report neither triggers a risk event nor performs a password change, session revocation, or recovery-flow test. Security Defaults is not an alternative for this row.

## Control 6: Disable ordinary-user application consent

**Report recommendation:** Ensure user consent to apps accessing company data on their behalf is not allowed

### Implement

In **Microsoft Entra admin center > Entra ID > Enterprise apps > Consent and permissions > User consent settings**, set **User consent for applications** to **Do not allow user consent**, then save.

Script 30 removes ordinary-user self-consent assignments while preserving unrelated assignments, such as developer consent for owned resources.

### Exact recognition and exceptions

Script 99 reads `defaultUserRolePermissions.permissionGrantPoliciesAssigned` from `/policies/authorizationPolicy`. The collection must be returned, and no entry may match either of these case-insensitive patterns:

```text
^managePermissionGrantsForSelf\.
(^|\.)user-default
```

An explicitly returned empty collection passes. A missing/null collection produces `UNKNOWN`, not a presumed disabled state.

The usual `managePermissionGrantsForSelf.microsoft-user-default-low` assignment fails even though it limits consent to verified publishers and low-impact permissions. Broad user consent, limited self-consent, or a custom policy assigned through the same self-consent prefix does not meet this exercise's requirement.

An assignment such as `managePermissionGrantsForOwnedResource.DeveloperConsent` can remain and still pass. Do not empty the entire assignment collection merely to obtain a green result.

This check does not revoke or inventory existing OAuth consent grants, disable administrator consent, prevent application registration, or verify an admin-consent workflow. Existing application access can continue after self-consent is disabled. Changing app-registration permission or enabling an approval workflow alone does not satisfy this row.

The checker examines recognized assignments on the default user role; it does not exhaustively evaluate all custom consent policies, custom roles, or future assignment formats. Review unusual configurations manually.

The separate Baseline Security Mode inventory in scripts 62-69 has a limited-user-consent recommendation with a different expectation. Do not re-enable low-risk self-consent to satisfy that inventory and expect this stricter script 99 row to stay implemented.

## Common scope for Teams controls 7-9

Open **Microsoft Teams admin center > Meetings > Meeting policies > Global (Org-wide default)**. Edit this policy, not a similarly named custom policy, a single meeting's options, an events policy, or the separate **Meeting settings** page.

The report calls `Get-CsTeamsMeetingPolicy -Identity Global` and requires exactly one object with identity `Global`. It does not enumerate custom policies, evaluate user/group assignments, inspect sensitivity labels/templates, or join a meeting.

Consequently, a perfectly configured custom policy assigned to all users can still leave these rows failing if Global has different values. Conversely, compliant Global values can pass even while custom-policy organizers use less restrictive settings.

Changes can take up to 24 hours to take effect. A configured value read from Global is not proof that an existing meeting has adopted it. Use manual effective-policy and meeting checks if the assessment requires that additional assurance.

A service read failure makes dependent Teams rows `UNKNOWN`. A missing property also makes its row `UNKNOWN`; a readable different value produces `NOT-CONFIGURED`.

## Control 7: Invited-user Teams lobby bypass

**Report recommendation:** Only invited users should be automatically admitted to Teams meetings

### Implement and recognize

In Global's **Meeting join & lobby** section, set **Who can bypass the lobby** to **People who were invited**, then save.

The exact expected PowerShell value is:

```text
Global.AutoAdmittedUsers = InvitedUsers
```

Script 40 sets this property.

### Exceptions

The check is an equality test, not a ranking of more or less restrictive options. **Only organizers and co-organizers** (`OrganizerOnly`) does not pass even though it is more restrictive. Neither do organization-only, trusted-organization, or Everyone values.

This is a default organizers can change through meeting options unless another feature enforces it. Invited participants can include eligible recipients of forwarded invitations and invited distribution-list members; it does not mean only names personally entered by the original organizer.

An uninvited participant waiting in the lobby may still be admitted. This setting is not a prohibition on that participant joining. Dial-in bypass, who can admit from the lobby, and anonymous-join permission are separate controls and are not validated by this row.

## Control 8: Organizer-only default Teams presenters

**Report recommendation:** Configure which users are allowed to present in Teams meetings

### Implement and recognize

In Global's **Content sharing** section, set **Who can present** to **Only organizers and co-organizers**, then save.

The exact expected PowerShell value is:

```text
Global.DesignatedPresenterRoleMode = OrganizerOnlyUserOverride
```

Script 42 sets this property. Some client or older documentation labels use **Only me**; use the returned policy value above as the report's decisive evidence.

### Exceptions

**People in my org and guests**, **Everyone**, and other enum values do not pass. Modifying one meeting's presenter list or a custom policy does not change this row.

`UserOverride` is significant: this is the default presenter choice, not a tenant-wide immutable prohibition. Organizers can change meeting options or participant roles. Co-organizers are included in the current portal behavior even though the script name says organizer-only.

The report does not check screen-sharing restrictions, give/request-control settings, external participant control, or whether labels/templates enforce a particular meeting value.

## Control 9: Disable anonymous Teams meeting join

**Report recommendation:** Restrict anonymous users from joining meetings

### Implement and recognize

In Global's **Meeting join & lobby** section, set **Anonymous users can join a meeting** to **Off**, then save.

The expected property must be an actual Boolean:

```text
Global.AllowAnonymousUsersToJoinMeeting = false
```

Script 44 sets this property. A missing value or a string such as `"false"` is not accepted as verified Boolean evidence.

### Exceptions

An organization-wide anonymous-join setting under **Meetings > Meeting settings** may affect real behavior, but the script does not read it as a substitute for this Global property.

Turning off **Anonymous users and dial-in callers can start a meeting** is not the same as preventing anonymous users from joining an already started meeting. Making anonymous users wait in the lobby is also not equivalent.

Authenticated guests are not automatically anonymous users. This row does not require disabling guest access, external access, or dial-in participation. It also does not prove that organizers assigned custom meeting policies block anonymous join.

## Control 10: Self-service password reset for all users

**Report recommendation:** Ensure 'Self service password reset enabled' is set to 'All'

### Implement

Open **Microsoft Entra admin center > Entra ID > Password reset > Properties**, set **Self service password reset enabled** to **All**, and select **Save**.

The direct page used by script 60 is:

<https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties>

Script 60 only opens that URL. It does not set or verify the scope. **Selected**, even if its selected group contains every current user, is not the required **All** value.

### Critical grading limitation: operator confirmation

Script 99 does not read the exact tenant-wide None/Selected/All property. Its `SsprAllScopeConfirmed` switch defaults to **true**:

| Invocation/confirmation state | Row 10 result |
| --- | --- |
| Switch omitted | `IMPLEMENTED`, recording the built-in assumption that the operator confirmed All |
| `-SsprAllScopeConfirmed:$true` or `-SsprAllScopeConfirmed` | `IMPLEMENTED`, based on confirmation |
| `-SsprAllScopeConfirmed:$false` | `UNKNOWN`, because All has not been confirmed |

**Therefore, row 10 can be green even when the tenant was never configured for All. Do not award this control solely from the default report result.**

The assessor should verify the saved Properties page in the intended tenant and retain dated evidence identifying that tenant. Until this is done, run script 99 with `-SsprAllScopeConfirmed:$false`. The switch records an assertion; it does not change SSPR configuration.

If the portal shows None or Selected, the human assessment should record the unmet requirement. The script itself does not discover that value and will report `UNKNOWN` when confirmation is false, not automatically `NOT-CONFIGURED`.

### Registration and operational exceptions

SSPR registration/capability counts are advisory for enabled member accounts. Missing registration data, users reported not registered/capable, and report latency do not override operator confirmation. A fully populated registration report also does not establish that the scope is All.

Script 61's registration diagnostic is not independent proof of this tenant setting. Administrator SSPR behavior is also not proof: administrators have distinct default reset rules, including stronger verification requirements and trial-related exceptions. Use a normal non-administrator user if a functional reset test is part of the assessment.

The **All** scope alone does not establish that every user has appropriate licenses, enough permitted recovery methods, or working password writeback. Hybrid users may need properly configured and licensed writeback. Guest identities and administrator-specific restrictions require separate review. None of these dependencies is certified by row 10.

## Run script 99 and collect assessment evidence

### Establish read access

Run from a normal PowerShell 7.2+ session. Install tools with script 00 if not already installed, and substitute the actual tenant GUID when prompted:

```powershell
Set-Location 'C:\GitHub\m365-harden-lab\scripts'
$TenantId = [guid](Read-Host 'Tenant ID for this assessment')

.\01-Test-TenantConnections.ps1 `
    -TenantId $TenantId `
    -IncludeTeams `
    -ConsentForAllScripts:$false
```

Always passing `-TenantId` makes the target explicit. Omitting it requires a suitable existing delegated Graph context in the same process. For the browser-PKCE flow provided by script 01, continue to pass the tenant explicitly to script 99.

For certificate-based Teams authentication, supply the existing `-TeamsApplicationId` and exactly one of `-TeamsCertificateThumbprint` or `-TeamsCertificatePath` to both connection validation and the report as needed. Script 07 can verify that application first. A thumbprint needs its accessible private key on the assessment machine; copying a thumbprint alone does not transfer a certificate. Keep PFX files and passwords out of the repository.

### Run without assuming SSPR has been verified

Start with explicit false SSPR confirmation. Populate the exclusion arrays only with assessor-approved GUIDs before the run; empty arrays approve no exclusions.

```powershell
$reportParameters = @{
    TenantId = $TenantId
    ApprovedExcludedUserId = @()
    ApprovedExcludedGroupId = @()
    ApprovedExcludedRoleId = @()
    SsprAllScopeConfirmed = $false
    SnapshotDirectory = 'C:\SecureM365Snapshots'
    PassThru = $true
}

$results = .\99-Test-M365RecommendationStatus.ps1 @reportParameters
$results | Format-Table Number, Status, Recommendation -Wrap
```

Only after the assessor has verified **SSPR = All** in the correct tenant:

```powershell
$reportParameters.SsprAllScopeConfirmed = $true
$results = .\99-Test-M365RecommendationStatus.ps1 @reportParameters
```

A successful process exit is not the assessment result. Script 99 can complete and save its report with `NOT-CONFIGURED` or `UNKNOWN` rows. Inspect all ten returned statuses and their evidence:

```powershell
$results |
    Where-Object Status -ne 'IMPLEMENTED' |
    Format-Table Number, Status, Evidence -Wrap

($results | Where-Object Number -eq 5).PolicyConfiguration |
    Format-List *
```

### Evidence to retain

Each completed run creates a timestamped JSON file under `C:\SecureM365Snapshots` by default. The filename includes the tenant GUID and a UTC timestamp. The directory is created if needed, existing snapshot files are not overwritten, and a write failure stops the report rather than silently omitting the snapshot.

Rows contain `Number`, `Recommendation`, `Status`, `Evidence`, the compatibility alias `Details`, `TenantId`, and `CheckedAt`. Each row also has `PolicyConfiguration`: it is populated for rows 1, 2, 4, and 5 when their shared assessment completes, and is null for the other rows or after a caught assessment failure.

For an assessment record, retain:

- The unedited JSON snapshot, the exact invocation parameters, and the script/common-module revision used.
- The approved exception register, including object/template IDs, justification, approval, and any expiry.
- CA policy details showing assignments, application/client scope, conditions, grants, state, and required session controls. Snapshot policy summaries are not full raw policy exports.
- Global Teams meeting-policy evidence and any separately required review of custom-policy assignments.
- Independent, dated **SSPR Properties = All** evidence for the assessed tenant.
- Any separately required functional evidence, such as a controlled sign-in or reset test. Script 99 does not generate that evidence.

Keep these records in protected assessment storage. They can contain tenant, user, group, role, application, and policy identifiers; do not commit real tenant snapshots or credentials to the repository.

## Exceptions, troubleshooting, and assessor decisions

| Situation | How to interpret or resolve it |
| --- | --- |
| A CA policy is visible but the row fails | Check the actual state, direct All-users/role assignment, grant operator, risk level, and required session values. A policy name is not evidence of its contents. |
| MFA/risk row is green with `CoverageVerified = false` | The enabled-policy requirement passed, not full coverage. Review exclusions and resource/client/condition restrictions against the exercise's agreed scope. |
| Administrator row passes but a role is unprotected | Role presence is enough for status. Inspect the coverage advisory and review the actual role population; do not equate the title with exhaustive coverage. |
| Legacy row is `UNKNOWN` after adding an exclusion | Verify the exclusion was authorized, then supply its correct ID to script 99. Also check both legacy client types and the strict broad-scope restrictions. |
| A stricter Teams value fails | Rows 7 and 8 require particular property values, not a monotonic security score. Document a manual exception if the approved design intentionally uses a different value; do not silently equate it with a pass. |
| Missing Microsoft Graph data | Read failures normally make dependent rows `UNKNOWN`. Rows 1-3 require a usable Security Defaults read; if that read fails, those rows cannot complete their normal assessment. |
| CA read fails but Security Defaults is verified enabled | Rows 1 and 2 can still pass from Security Defaults, with policy-presence fields left unknown. Row 3 can also pass through its Security Defaults branch. Rows 4 and 5 still require readable CA policies. |
| User, registration, or role data is missing | This is advisory for a detected MFA configuration, and registration is advisory for operator-confirmed SSPR. The risk rows do not depend on these datasets. Preserve the warning; do not turn missing data into a claim of readiness. |
| Teams returns Forbidden/Access Denied | Verify the Teams identity's active role and correct tenant, allow propagation, disconnect Teams, and rerun script 01 with `-IncludeTeams`. Graph scopes alone do not fix Teams authorization. |
| Missing modules, failed initial authentication, or unwritable snapshot directory | The script can stop before delivering a complete report. Correct the assessment environment; do not treat an incomplete run as ten evaluated controls. |
| New settings are not reflected yet | Allow service propagation and rerun. Authentication-method reporting commonly lags up to 36 hours, with occasional longer outliers; Teams policy effects can take up to 24 hours. Do not use those delays to justify an unverified pass. |
| SSPR is green with no portal evidence | The default confirmation is insufficient grading evidence. Verify the saved tenant setting or rerun with confirmation false. |

Script 99 loads its datasets before printing the first row, so warnings may appear before check 1. Review them with the corresponding evidence rather than assuming they all relate to the first control.

For a straightforward supported implementation, use broad all-user MFA, a legacy-client block, separate sign-in-risk and user-risk policies, disabled ordinary-user consent, the three exact Global Teams settings, and manually verified SSPR = All. A broad all-user MFA policy can also satisfy the administrator MFA row. Keep emergency exclusions deliberate and documented.

Ten green rows are the report's configuration result, not a comprehensive Microsoft 365 security certification. The report does not audit every administrative role assignment, effective custom Teams policy, existing consent grant, legacy-service setting, workload identity, authentication method, or successful remediation path.

## Sources and related procedures

### Repository sources

- `scripts\99-Test-M365RecommendationStatus.ps1`: the ten checks, service readers, status handling, snapshots, and SSPR confirmation.
- `scripts\SecureM365.Common.psm1`: `Get-SecureM365MfaPolicyAssessment`, the MFA-grant and CA-scope helpers, and Global Teams policy validation.
- `tests\MfaPolicy.Tests.ps1`, `tests\SignInRiskPolicy.Tests.ps1`, and `tests\UserRiskPolicy.Tests.ps1`: regression scenarios for recognized policies, rejected variants, exclusions, and advisory-only evidence.
- `tests\M365RecommendationStatus.Tests.ps1`: report inventory, SSPR confirmation, evidence, and snapshot behavior.
- The corresponding procedures in `videos`, especially the Conditional Access, application-consent, Global Teams meeting-policy, and SSPR guides.

The standalone checks in scripts 11, 13, 17, and 19 share the current MFA/risk evaluator with script 99. Do not assume that every other numbered diagnostic has identical output or scoring; script 99 is the report specified for this assessment.

### Microsoft references

- [Security Defaults, its protections, licensing, and transition to Conditional Access](https://learn.microsoft.com/entra/fundamentals/security-defaults)
- [Conditional Access authentication strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
- [Block legacy authentication with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication)
- [Require MFA for elevated sign-in risk](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in)
- [Require remediation for risky users](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user)
- [Graph grant controls, remediation combinations, and the evolving-enum header](https://learn.microsoft.com/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0)
- [Adaptive risk remediation behavior and guest/external-user limitations](https://learn.microsoft.com/entra/id-protection/concept-identity-protection-policies#require-risk-remediation-control)
- [Configure user consent and preserve owned-resource consent](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
- [Teams meeting-policy PowerShell properties](https://learn.microsoft.com/powershell/module/microsoftteams/set-csteamsmeetingpolicy?view=teams-ps)
- [Teams lobby behavior, invitations, defaults, and propagation](https://learn.microsoft.com/microsoftteams/who-can-bypass-meeting-lobby)
- [Teams presenter defaults and organizer overrides](https://learn.microsoft.com/microsoftteams/meeting-who-present-request-control)
- [Enable SSPR](https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-sspr)
- [SSPR licensing and hybrid writeback](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-licensing)
- [Administrator-specific password-reset rules](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy)
- [Authentication-method registration reporting and latency](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity)
