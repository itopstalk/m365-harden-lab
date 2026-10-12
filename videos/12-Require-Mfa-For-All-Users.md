---
title: Require MFA for all users
description: Create CA002 with all-user and all-resource scope using the built-in Multifactor authentication strength.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want all users covered by enforced MFA with only the approved emergency exclusions.
---

# Require MFA for all users

Create CA002 using the built-in **Multifactor authentication** strength. This policy targets all users and resources, not only people already registered for MFA.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [12-New-AllUserMfaPolicy.ps1](../scripts/12-New-AllUserMfaPolicy.ps1).

## Prerequisites

- An active **Conditional Access Administrator** role and appropriate Entra ID P1 or P2 licensing.
- The two prepared emergency accounts from [procedure 04](04-Create-Emergency-Access-Accounts.md).
- Users able to satisfy the built-in MFA authentication strength, with a reviewed registration and support plan.
- Security Defaults disabled as part of the reviewed [transition](09-Transition-From-Security-Defaults.md), if needed.

## Create CA002

Use a new custom Conditional Access policy rather than changing per-user MFA status or accepting a template's additional exclusions.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Conditional Access** > **Policies**.
3. Search for `CA002 - Require MFA for all users`.
4. If the name already exists, stop and review it; do not create a duplicate or silently update it.
5. Select **New policy**.
6. Enter **Name**: `CA002 - Require MFA for all users`.
7. Open **Users** or **Users or workload identities**.
8. Under **Include**, select **All users**.
9. Under **Exclude**, select **Users and groups**.
10. Select only the two emergency users identified in procedure 04.
11. Confirm the user selection with **Select** or **Done**.
12. Open **Target resources**.
13. Choose **Resources (formerly cloud apps)** as the target type.
14. Under **Include**, select **All resources (formerly 'All cloud apps')**.
15. Leave the resource **Exclude** list empty.
16. Leave **Conditions** unconfigured, including client apps, network/location, platforms, devices, and risk.
17. Open **Access controls** > **Grant**.
18. Select **Grant access**.
19. Select **Require authentication strength**.
20. Choose the built-in **Multifactor authentication** strength, sometimes labeled **Multifactor authentication strength**.
21. Leave all other grant controls unselected.
22. Set the control combination to **Require one of the selected controls**.
23. Select **Select**.
24. Leave **Session** controls unconfigured.
25. Set **Enable policy** to **On**.
26. Select **Create**.
27. Record the policy name and its portal URL.

If staging is necessary, choose **Report-only** at step 25 and later complete [procedure 20](20-Enable-Reviewed-Conditional-Access-Policy.md). The final state must be **On**.

## Expected configuration

| Setting | Value |
| --- | --- |
| Name | `CA002 - Require MFA for all users` |
| State | On / `enabled` |
| Users | All, excluding only the approved emergency users |
| Resources and client apps | All; no resource exclusions |
| Grant | Built-in Multifactor authentication strength |
| Strength ID | `00000000-0000-0000-0000-000000000002` |
| Grant operator | `OR`, with only the authentication-strength control selected |
| Session controls | None added |

Do not choose **Passwordless MFA**, **Phishing-resistant MFA**, or a custom strength for this script-equivalent configuration. Do not add **Require device to be marked as compliant** as an alternative; **MFA OR compliant device** would let users bypass MFA and would not satisfy script 99.

Do not automatically exclude guests, trusted locations, the current administrator, or synchronization roles. The script excludes only the emergency user IDs supplied to it. Any additional exception needs explicit review and matching approved-exclusion parameters for the report's separate coverage advisory.

Conditional Access MFA does not require changing the separate per-user MFA state to **Enabled** or **Enforced**. Scripts 13 and 99 detect CA002's enabled all-user MFA configuration independently of user registration and Secure Score. They show the policy ID, name, state, and exclusions; disabled and report-only policies do not pass.

An enabled policy does not wait for users to register before its requirements
apply to a covered sign-in. Registration, exceptions, and complete coverage are
separate advisories. Emergency exclusions and users without registered methods
therefore do not negate the enabled-policy result, but the result is not proof
that every user or sign-in is protected.

## Related content

- [Require MFA for all users using authentication strength](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength)
- [Conditional Access authentication strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
