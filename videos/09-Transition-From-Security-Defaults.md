---
title: Transition from Security Defaults to the lab Conditional Access policies
description: Disable Security Defaults only as part of a prepared transition to enforced replacement Conditional Access policies.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want to transition to Conditional Access without leaving the tenant unintentionally unprotected.
---

# Transition from Security Defaults to the lab Conditional Access policies

Use this procedure only when Security Defaults is enabled and the tenant is ready to move to the licensed Conditional Access configuration. The risk recommendations in script 99 cannot be implemented by leaving Security Defaults enabled instead of configuring risk policies.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script relationship:** Prerequisite for scripts 10, 12, 14, 16, and 18. None of those scripts disables Security Defaults.

## Prerequisites

- An active **Conditional Access Administrator** role.
- The Conditional Access and risk-policy licensing listed in the [series prerequisites](README.md#prerequisites).
- Completion of the [emergency-account preparation](04-Create-Emergency-Access-Accounts.md), including usable phishing-resistant authentication and the recorded user object IDs.
- MFA readiness for affected users and confirmation that required clients use modern authentication.
- A reviewed change window and the procedures for [CA001](10-Require-Mfa-For-Administrators.md), [CA002](12-Require-Mfa-For-All-Users.md), and [CA003](14-Block-Legacy-Authentication.md) ready to complete immediately.

> [!WARNING]
> Do not disable Security Defaults just to fix a Teams or PowerShell sign-in problem. Disabling it removes its protections. Enable the replacement Conditional Access policies immediately, and do not leave only report-only policies as the tenant's protection.

## Change the security mode

Skip this change if Security Defaults is already disabled. Do not turn it on and off just to demonstrate the control.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **Overview** > **Properties**.
3. Select **Manage security defaults**.
4. If the setting is **Enabled**, select **Disabled (not recommended)**.
5. If asked for a reason, select the option describing the planned use of Conditional Access.
6. Select **Save**.
7. Immediately complete the CA001, CA002, and CA003 creation procedures with **Enable policy = On**.
8. Complete CA004 and CA005 once their MFA and password-remediation prerequisites are ready.

For a tenant already protected by existing Conditional Access policies, retain that protection while evaluating staged replacements. If the lab policies were created in report-only mode, use [procedure 20](20-Enable-Reviewed-Conditional-Access-Policy.md) to enforce them after review.

## Expected configuration

Security Defaults is disabled and the replacement lab policies are enforced. This transition is an explicit prerequisite, not something script 99 performs.

The five lab policies are not a claim to reproduce every Security Defaults behavior. For example, blocking legacy authentication clients in CA003 is not the same as blocking the OAuth device code flow. Review any additional organizational protection requirements separately rather than silently adding different controls to the lab policies.

## Related content

- [Disable Security Defaults and move to Conditional Access](https://learn.microsoft.com/entra/fundamentals/security-defaults#disabling-security-defaults)
- [Plan a Conditional Access deployment](https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access)
