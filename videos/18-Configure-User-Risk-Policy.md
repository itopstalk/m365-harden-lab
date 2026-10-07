---
title: Require remediation for high-risk users
description: Create CA005 through the current Entra risk-remediation workflow accepted by the final Microsoft 365 lab report.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want high-risk users required to remediate risk and reauthenticate before accessing resources.
---

# Require remediation for high-risk users

Create CA005 with high user risk, MFA authentication strength, and mandatory every-time reauthentication. This procedure uses the current documented **Require risk remediation** portal workflow accepted by script 99.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [18-New-UserRiskPolicy.ps1](../scripts/18-New-UserRiskPolicy.ps1), with the browser-control difference below.

## Prerequisites

- An active **Conditional Access Administrator** role.
- Microsoft Entra ID P2 entitlement for users in scope.
- The prepared emergency accounts from [procedure 04](04-Create-Emergency-Access-Accounts.md).
- Completion of [SSPR for all users](60-Enable-Sspr-For-All-Users.md), usable registered MFA, and password-remediation readiness. Hybrid users need the applicable password-writeback prerequisites.
- Security Defaults disabled and the broad MFA/legacy-authentication policies already in place.
- Availability of **Require risk remediation** in the tenant's Conditional Access grant controls.

> [!IMPORTANT]
> Script 18 submits `passwordChange` with MFA authentication strength. Microsoft's current portal instructions use `riskRemediation`, which supports password-based and passwordless remediation. This guide targets the same **script 99 recommendation outcome**, not identical behavior for every authentication method. Script 99 explicitly accepts either remediation control; script 19 still specifically requires `passwordChange`.

## Create CA005

Configure **User risk**, not **Sign-in risk**. Create one remediation policy; do not combine the old and new remediation grants.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Conditional Access** > **Policies**.
3. Search for `CA005 - Require remediation for high user risk`.
4. If that name already exists, stop and review the policy. Do not replace a script-created policy merely to record the newer UI.
5. Select **New policy**.
6. Enter **Name**: `CA005 - Require remediation for high user risk`.
7. Open **Users** or **Users or workload identities**.
8. Under **Include**, select **All users**.
9. Under **Exclude**, select **Users and groups**.
10. Select only the two emergency users.
11. Confirm the user selection with **Select** or **Done**.
12. Open **Target resources**.
13. Choose **Resources (formerly cloud apps)**.
14. Under **Include**, select **All resources (formerly 'All cloud apps')**.
15. Leave the resource **Exclude** list empty.
16. Open **Conditions** > **User risk**.
17. Set **Configure** to **Yes**.
18. Select **High** only.
19. Select **Done**.
20. Leave **Sign-in risk**, **Client apps**, and every other condition unconfigured.
21. Open **Access controls** > **Grant**.
22. Select **Grant access**.
23. Select **Require risk remediation**.
24. In the automatically selected **Require authentication strength** control, choose the built-in **Multifactor authentication** strength.
25. Set the control combination to **Require all the selected controls**. MFA and remediation must both be required, not alternatives.
26. Leave unrelated grant controls unselected, including **Require password change** as a separate additional control.
27. Select **Select**.
28. Open **Session**.
29. Retain the automatically required **Sign-in frequency = Every time** control.
30. Leave all other session controls unselected.
31. Select **Select**.
32. Set **Enable policy** to **On**.
33. Select **Create**.
34. Record the policy name, portal URL, and use of the modern risk-remediation control.

If **Require risk remediation** or its mandatory session configuration is unavailable, stop for a licensing/feature review. MFA alone, an old Identity Protection toggle, or a policy with no remediation control is not a substitute.

For staging, use **Report-only** at step 32 and later complete [procedure 20](20-Enable-Reviewed-Conditional-Access-Policy.md).

## Expected configuration

| Setting | Browser policy value |
| --- | --- |
| Name | `CA005 - Require remediation for high user risk` |
| State | On / `enabled` |
| Users | All, excluding only the approved emergency users |
| Resources and client apps | All; no resource exclusions or client-app restriction |
| User risk | `high` |
| Sign-in risk | Not configured |
| Grant combination | `AND` |
| Remediation grant | `riskRemediation`, rather than script 18's `passwordChange` |
| Authentication strength | Multifactor authentication, ID `00000000-0000-0000-0000-000000000002` |
| Sign-in frequency | Enabled; `frequencyInterval = everyTime` |
| Reauthentication scope expected by script 99 | `authenticationType = primaryAndSecondaryAuthentication` |

Exactly one remediation grant must be selected. Keep the authentication strength in the same policy; relying only on a different MFA policy is not the shape script 99 checks for the modern remediation control.

Do not add location exceptions, device compliance requirements, or application filters. Do not create real risky-user events just to complete this recording.

## Related content

- [Require remediation for risky users](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user)
- [Conditional Access grant controls](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant#require-risk-remediation)
- [Configure risk-based MFA and remediation](https://learn.microsoft.com/entra/identity/authentication/tutorial-risk-based-sspr-mfa)
