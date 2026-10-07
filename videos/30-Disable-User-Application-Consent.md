---
title: Disable ordinary-user application consent
description: Prevent users from granting new application consent on their own behalf through the Microsoft Entra admin center.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want new ordinary-user app consent blocked without revoking existing grants or changing unrelated app settings.
---

# Disable ordinary-user application consent

Prevent ordinary users from granting new consent to applications that request access to company data on their behalf. This does not revoke existing application consent or disable administrator consent.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [30-Disable-UserApplicationConsent.ps1](../scripts/30-Disable-UserApplicationConsent.ps1).

## Prerequisites

- An existing, active **Global Administrator** for the portal operation. Current Microsoft documentation requires this role for the admin-center path, even though the script's Graph path supports Privileged Role Administrator.
- Approval for the effect on future user consent requests.
- Review of any custom consent/developer policies already in use. The script preserves non-user-self-consent assignments; the portal does not expose the complete underlying assignment collection.

## Change user consent settings

Change the user-consent setting, not the unrelated setting that allows users to register applications.

1. Sign in to the **Microsoft Entra admin center** using the authorized administrator.
2. Open **Entra ID** > **Enterprise apps**. In older navigation, use **Identity** > **Applications** > **Enterprise applications**.
3. Select **Consent and permissions**.
4. Select **User consent settings**.
5. Under **User consent for applications**, select **Do not allow user consent**.
6. Select **Save**.

If the required control is unavailable, stop and confirm the role and tenant. Do not choose a different consent option to complete the recording.

## Expected configuration

Ordinary users cannot grant new self-consent. The final script expects no default-user permission-grant assignment beginning with `managePermissionGrantsForSelf.` and no matching `user-default` consent policy.

**Allow user consent for apps from verified publishers, for selected permissions** is not equivalent. It still allows user consent and does not satisfy script 99. A Microsoft-managed or recommended consent choice is also not a substitute for explicitly selecting **Do not allow user consent**.

Leave app-registration permissions, existing enterprise-app grants, developer-owned-resource consent, and the admin consent workflow unchanged. Do not revoke existing grants or enable an approval workflow as an extra step: script 30 does neither.

If custom non-self-consent assignments require exact preservation, obtain an authorized review rather than assuming this page exposes all of them. Do not empty an underlying permission collection or use Graph Explorer as an undocumented workaround in this admin-center-only series.

The Baseline Security Mode inventory in script 62 expects limited low-risk consent for `ENTRA-APP-002`. That is a different, incompatible exact expectation; do not re-enable consent after this procedure to satisfy that row.

## Related content

- [Configure user consent settings](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
- [User and admin consent overview](https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview)
