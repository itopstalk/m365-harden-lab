---
title: Block legacy authentication
description: Create CA003 to block Exchange ActiveSync and other legacy clients for all users and resources.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want legacy authentication blocked without accidentally blocking modern browser and desktop sign-in.
---

# Block legacy authentication

Create CA003 to block the two legacy client categories used by script 14. The script's default has no user exclusions.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [14-New-BlockLegacyAuthenticationPolicy.ps1](../scripts/14-New-BlockLegacyAuthenticationPolicy.ps1).

## Prerequisites

- An active **Conditional Access Administrator** role and appropriate Entra ID P1 or P2 licensing.
- Required mail clients, devices, and services migrated to modern authentication.
- Prepared emergency accounts that can use modern, phishing-resistant sign-in.
- Security Defaults disabled as part of the reviewed [transition](09-Transition-From-Security-Defaults.md), if needed.
- A documented, approved list if the lab deliberately uses the script's optional `TemporaryExceptionAccountId` parameter. The default procedure uses none.

## Create CA003

The client-app selection is critical: blocking **all** client types would block modern access too.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Conditional Access** > **Policies**.
3. Search for `CA003 - Block legacy authentication`.
4. If the name already exists, stop and review the existing policy.
5. Select **New policy**.
6. Enter **Name**: `CA003 - Block legacy authentication`.
7. Open **Users** or **Users or workload identities**.
8. Under **Include**, select **All users**.
9. Leave **Exclude** empty to reproduce the script's default.
10. Confirm the user selection with **Select** or **Done**.
11. Open **Target resources**.
12. Choose **Resources (formerly cloud apps)**.
13. Under **Include**, select **All resources (formerly 'All cloud apps')**.
14. Leave the resource **Exclude** list empty.
15. Open **Conditions** > **Client apps**.
16. Set **Configure** to **Yes**.
17. Select **Exchange ActiveSync clients**.
18. Select **Other clients**.
19. Clear **Browser** and **Mobile apps and desktop clients** if they are selected.
20. Select **Done**.
21. Leave every other condition unconfigured.
22. Open **Access controls** > **Grant**.
23. Select **Block access**.
24. Select **Select**.
25. Leave **Session** controls unconfigured.
26. Set **Enable policy** to **On**.
27. Select **Create**.
28. Record the policy name and its portal URL.

If the impact is not yet reviewed, use **Report-only** at step 26 and later complete [procedure 20](20-Enable-Reviewed-Conditional-Access-Policy.md). Do not mistake successful creation in report-only mode for a block.

## Handle an explicitly approved temporary exception

Microsoft's general deployment guidance recommends a lockout-prevention exclusion. Script 14 instead defaults to an empty exception list, unlike the MFA and risk scripts. That difference is deliberate in this procedure.

If an exception is necessary, select its specific users under **Users > Exclude > Users and groups** at step 9. Record the user object IDs, owner, and removal plan. This is the browser equivalent of supplying `TemporaryExceptionAccountId`, not the script's default. Add those IDs to `ApprovedExcludedUserId` when running script 99. Do not silently accept an automatic current-user exclusion.

## Expected configuration

| Setting | Value |
| --- | --- |
| Name | `CA003 - Block legacy authentication` |
| State | On / `enabled` |
| Users | All; no exclusions by default |
| Resources | All; no exclusions |
| Client apps | `exchangeActiveSync` and `other` only |
| Grant | `block` |
| Other conditions/session controls | None added |

This is a Conditional Access legacy-client block. It is not an Exchange mailbox protocol change, an organization-wide EWS switch, or an OAuth device-code-flow block.

## Related content

- [Block legacy authentication with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication)
- [Emergency access account guidance](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
