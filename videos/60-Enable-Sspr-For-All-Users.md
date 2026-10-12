---
title: Enable self-service password reset for all users
description: Set the Microsoft Entra self-service password reset scope to All using the admin center.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want all users in scope for password reset so that the SSPR recommendation is genuinely configured.
---

# Enable self-service password reset for all users

Set the tenant's self-service password reset (SSPR) scope to **All**. This is the manual configuration task for which script 60 opens the browser.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [60-Open-SsprSettings.ps1](../scripts/60-Open-SsprSettings.ps1), with the intended outcome recorded by script 99.

## Prerequisites

- An active **User Administrator** role as used by the lab's permission checker, or **Authentication Policy Administrator**.
- Licensing that covers SSPR for the affected users.
- Allowed authentication methods and sufficient registered recovery methods for users who must actually perform a reset.
- Working password writeback if the lab includes synchronized users whose passwords must be changed on-premises.

## Set the SSPR scope

Use the Entra Password reset page, not an individual user's Reset password command.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Password reset**.
3. Select **Properties**.
4. Under **Self service password reset enabled**, select **All**.
5. Select **Save**.
6. Record that **All** was saved for this tenant in the protected lab record.

If the navigation is difficult to locate, use the same [Password reset Properties page](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties) opened by script 60.

## Expected configuration and boundaries

**Self service password reset enabled = All** is the required result. **Selected**, even with a group that currently contains every user, is not the same tenant scope.

Leave unrelated registration reminders, reset-method counts, notifications, and customization settings unchanged to preserve the scripts' scope. Enabling SSPR does not register recovery methods on users' behalf. Since the legacy authentication-method management retirement, method availability is managed through **Entra ID > Authentication methods**, not by relying on old MFA/SSPR method checkboxes.

Microsoft Graph does not expose the exact **None / Selected / All** choice to this repository's final checker. Script 99 defaults `SsprAllScopeConfirmed` to true and records operator confirmation. Do not rely on that default until these steps are complete. If the scope has not been confirmed, run the report with `-SsprAllScopeConfirmed:$false`.

Script 61's registration data and script 99's advisory registration notes can lag by up to 36 hours. They are not a replacement for setting this property.

## Related content

- [Enable Microsoft Entra self-service password reset](https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-sspr)
- [SSPR licensing](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-licensing)
- [SSPR policy and administrator differences](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy)
