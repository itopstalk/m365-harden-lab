---
title: Enable a reviewed report-only Conditional Access policy
description: Change an approved lab policy from Report-only to On without changing its assignments or controls.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want an approved staged policy enforced without changing its reviewed configuration.
---

# Enable a reviewed report-only Conditional Access policy

Change a deliberately staged policy from **Report-only** to **On**. This procedure changes only the policy state, matching script 20.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [20-Enable-ReviewedConditionalAccessPolicy.ps1](../scripts/20-Enable-ReviewedConditionalAccessPolicy.ps1).

## Prerequisites

- An active **Conditional Access Administrator** role and licensing for the policy's controls.
- A specific existing policy created in **Report-only** mode.
- The recorded policy identity or portal URL, approved assignments and exclusions, and completed impact review.
- Working emergency access and users ready for the policy's MFA, modern-authentication, or remediation requirements.
- Security Defaults disabled as part of the approved transition, if applicable.

## Turn on the reviewed policy

Use this procedure once for each staged CA001-CA005 policy. The default creation guides already finish with **On**, so they do not need this change.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Conditional Access** > **Policies**.
3. Open the specifically approved policy, using its recorded portal URL or identity to disambiguate any similar names.
4. If **Enable policy** is already **On**, make no change and finish.
5. If its state is **Off**, stop. Script 20 also refuses to enable a disabled policy through this report-only promotion path.
6. For a **Report-only** policy, confirm that the displayed assignments and controls are still the configuration that was approved.
7. Change **Enable policy** from **Report-only** to **On**.
8. Select **Save**.
9. Repeat for the next specifically approved report-only policy, if any.

> [!WARNING]
> Saving **On** begins enforcement. Do not change grant controls or add broad exceptions at the same time; that would be a different configuration from the one reviewed.

## Expected configuration

The selected policy has `state = enabled`. Its name, users, emergency exclusions, target resources, conditions, grants, and session controls are unchanged.

If a newly created policy is not yet visible, allow propagation and reopen the policy list. Do not create a second policy to work around a delayed read.

## Related content

- [Conditional Access report-only mode](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only)
- [Plan a Conditional Access deployment](https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access)
