---
title: Require MFA for the lab's administrator roles
description: Create CA001 with the exact administrator role scope and MFA grant used by script 10.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want administrator access protected by MFA while preserving the approved emergency access exclusions.
---

# Require MFA for the lab's administrator roles

Create CA001 to require MFA for the 16 built-in roles selected by script 10. The policy covers all resources and excludes the two emergency users.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [10-New-AdminMfaPolicy.ps1](../scripts/10-New-AdminMfaPolicy.ps1).

## Prerequisites

- An active **Conditional Access Administrator** role and appropriate Entra ID P1 or P2 licensing.
- The two prepared emergency accounts and user object IDs from [procedure 04](04-Create-Emergency-Access-Accounts.md).
- Usable MFA methods for the affected administrators.
- Security Defaults disabled as part of the reviewed [Conditional Access transition](09-Transition-From-Security-Defaults.md), if it was enabled.

## Create CA001

Select exactly these 16 roles, including Authentication Policy Administrator and Identity Governance Administrator. Do not replace the role selection with a manually maintained group of current administrators.

| Role | Role |
| --- | --- |
| Global Administrator | Helpdesk Administrator |
| Application Administrator | Identity Governance Administrator |
| Authentication Administrator | Password Administrator |
| Authentication Policy Administrator | Privileged Authentication Administrator |
| Billing Administrator | Privileged Role Administrator |
| Cloud Application Administrator | Security Administrator |
| Conditional Access Administrator | SharePoint Administrator |
| Exchange Administrator | User Administrator |

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Conditional Access** > **Policies**.
3. Search for `CA001 - Require MFA for administrator roles`.
4. If that name already exists, stop and review the existing policy instead of creating a duplicate or modifying it. The script also refuses a name collision.
5. Select **New policy**.
6. Enter **Name**: `CA001 - Require MFA for administrator roles`.
7. Under **Assignments**, open **Users** or **Users or workload identities**.
8. Under **Include**, choose **Select users and groups** if needed to reveal the selectors, then select **Directory roles**.
9. Select every role in the table.
10. Under **Exclude**, select **Users and groups**.
11. Select the two emergency users, matching their sign-in names and recorded object IDs.
12. Confirm the user selection with **Select** or **Done**.
13. Open **Target resources**.
14. Set the target type to **Resources (formerly cloud apps)**.
15. Under **Include**, select **All resources (formerly 'All cloud apps')**.
16. Leave the resource **Exclude** list empty.
17. Leave **Conditions** unconfigured. In particular, do not restrict client apps, platforms, risk, devices, or locations.
18. Open **Access controls** > **Grant**.
19. Select **Grant access**.
20. Select only **Require multifactor authentication**.
21. Set the control combination to **Require one of the selected controls**.
22. Select **Select** to apply the grant choices.
23. Leave **Session** controls unconfigured.
24. Set **Enable policy** to **On**.
25. Select **Create**.
26. Record the policy name and its portal URL for later identification.

> [!WARNING]
> **On** enforces the policy immediately, matching the script's default. If administrators are not ready, create it as **Report-only** instead and use [procedure 20](20-Enable-Reviewed-Conditional-Access-Policy.md) after review. Report-only does not satisfy the final configuration.

## Expected configuration

| Setting | Value |
| --- | --- |
| Name | `CA001 - Require MFA for administrator roles` |
| State | On / `enabled` |
| Included identities | The 16 directory roles above |
| Excluded identities | Only the approved emergency users |
| Resources | All; no resource exclusions |
| Client apps | All, without a limiting client-app condition |
| Grant | `builtInControls = mfa`, `operator = OR` |
| Session controls | None added |

Use the **Require multifactor authentication** checkbox here, not an authentication-strength substitution, to match script 10. Microsoft recommends phishing-resistant MFA for administrators, but that is a different control from the one this script creates. **Microsoft Admin Portals** alone is also a narrower resource scope than this lab policy.

CA001 is not a promise to cover every possible administrative role. Complete CA002 as well; its all-user policy supplies the additional broad coverage used by the final report.

Scripts 11 and 99 report an enabled matching MFA policy as configured even when
the emergency accounts are excluded or administrators have not yet registered
MFA methods. They show the policy ID, name, state, and exclusions. Complete
coverage and registration readiness are separate advisories, not the pass
criterion. Use `ApprovedExcludedUserId` with the recorded emergency account IDs
for the coverage advisory; this is not necessary to detect CA001. A policy found
in disabled or report-only state does not pass.

## Related content

- [Require MFA for administrators](https://learn.microsoft.com/entra/identity/conditional-access/policy-old-require-mfa-admin)
- [Require MFA for all users in this lab](12-Require-Mfa-For-All-Users.md)
