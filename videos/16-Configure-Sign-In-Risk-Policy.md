---
title: Require MFA for medium and high sign-in risk
description: Create CA004 with MFA authentication strength and every-time reauthentication for medium and high sign-in risk.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want risky sign-ins to require fresh MFA while preserving approved emergency access.
---

# Require MFA for medium and high sign-in risk

Create CA004 to challenge medium- and high-risk sign-ins with MFA and every-time reauthentication. Use Conditional Access rather than an older standalone Identity Protection risk-policy page.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [16-New-SignInRiskPolicy.ps1](../scripts/16-New-SignInRiskPolicy.ps1).

## Prerequisites

- An active **Conditional Access Administrator** role.
- Microsoft Entra ID P2 entitlement for users in scope.
- The prepared emergency accounts from [procedure 04](04-Create-Emergency-Access-Accounts.md).
- Affected users already registered for usable MFA. A risky sign-in is not the time to depend on initial MFA registration.
- Security Defaults disabled and the broad MFA/legacy-authentication policies in place.

## Create CA004

Use **Sign-in risk**, not **User risk**, for this policy.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Conditional Access** > **Policies**.
3. Search for `CA004 - Require MFA for medium and high sign-in risk`.
4. If that name exists, stop and review it instead of creating or changing a policy automatically.
5. Select **New policy**.
6. Enter **Name**: `CA004 - Require MFA for medium and high sign-in risk`.
7. Open **Users** or **Users or workload identities**.
8. Under **Include**, select **All users**.
9. Under **Exclude**, select **Users and groups**.
10. Select only the two emergency users.
11. Confirm the user selection with **Select** or **Done**.
12. Open **Target resources**.
13. Choose **Resources (formerly cloud apps)**.
14. Under **Include**, select **All resources (formerly 'All cloud apps')**.
15. Leave the resource **Exclude** list empty.
16. Open **Conditions** > **Sign-in risk**.
17. Set **Configure** to **Yes**.
18. Select **Medium** and **High**, leaving **Low** unselected.
19. Select **Done**.
20. Leave **User risk**, **Client apps**, and all other conditions unconfigured.
21. Open **Access controls** > **Grant**.
22. Select **Grant access**.
23. Select **Require authentication strength**.
24. Choose the built-in **Multifactor authentication** strength.
25. Leave all other grant controls unselected.
26. Set the control combination to **Require one of the selected controls**.
27. Select **Select**.
28. Open **Session**.
29. Select **Sign-in frequency**.
30. Choose **Every time**, not a periodic number of hours or days.
31. Leave the other session controls unselected.
32. Select **Select**.
33. Set **Enable policy** to **On**.
34. Select **Create**.
35. Record the policy name and its portal URL.

For staging, use **Report-only** at step 33 and later complete [procedure 20](20-Enable-Reviewed-Conditional-Access-Policy.md).

## Expected configuration

| Setting | Value |
| --- | --- |
| Name | `CA004 - Require MFA for medium and high sign-in risk` |
| State | On / `enabled` |
| Users | All, excluding only the approved emergency users |
| Resources and client apps | All; no resource exclusions or client-app restriction |
| Sign-in risk | `medium`, `high` |
| User risk | Not configured |
| Authentication strength | Multifactor authentication, ID `00000000-0000-0000-0000-000000000002` |
| Grant operator | `OR`, with only the strength selected |
| Sign-in frequency | Enabled; `frequencyInterval = everyTime` |
| Reauthentication scope required by scripts 17 and 99 | `authenticationType = primaryAndSecondaryAuthentication` |

The intended session control requires fresh primary and secondary authentication, not merely a periodic refresh or an MFA-only session control. The documented portal workflow is **Sign-in frequency > Every time**. If the portal cannot save that configuration, stop for feature/licensing review rather than omitting it.

## Check the policy

Scripts 17 and 99 check for a matching **enabled** policy: All users, medium and
high sign-in risk, mandatory MFA, and every-time primary-and-secondary
reauthentication. They report the policy ID, name, state, risk levels, session
settings, and exclusions. Disabled and report-only policies do not pass, and
Security Defaults is not a substitute for a risk-based policy.

Exclusions and complete coverage are separate advisories, not reasons to reject
policy presence. Supplying the emergency IDs through `-ApprovedExcludedUserId`
lets the coverage advisory recognize those reviewed exclusions. Other conditions
and resource/client restrictions can still leave `CoverageVerified` false.
`Resolved = True` / `IMPLEMENTED` confirms configuration, not every sign-in's protection.

Script 17 returns one assessment without a Secure Score result. Script 99 includes
the same policy evidence in its `PolicyConfiguration` output and JSON snapshots.
Users do not need to generate a risky sign-in for either check to recognize the
enabled policy. Do not simulate attacks or risky activity as part of this recording.

Enrollment is still required before an actual risky sign-in: risk-based policies
block initial MFA registration during risky sessions.

## Related content

- [Require MFA for elevated sign-in risk](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in)
- [Configure risk-based MFA and remediation](https://learn.microsoft.com/entra/identity/authentication/tutorial-risk-based-sspr-mfa)
- [Sign-in frequency session control](https://learn.microsoft.com/graph/api/resources/signinfrequencysessioncontrol)
