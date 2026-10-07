---
title: Create cloud-only emergency access accounts
description: Create the two emergency users and permanent administrator assignments used by the Microsoft 365 hardening lab.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want emergency accounts available before enforcing access policies so that I can recover administrative access.
---

# Create cloud-only emergency access accounts

Create two emergency users in the tenant's original `onmicrosoft.com` domain and give them permanent, tenant-wide Global Administrator access. Record their user object IDs for the later Conditional Access exclusions and final report.

**Admin tools:** [Microsoft 365 admin center](https://admin.microsoft.com) and [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [04-New-EmergencyAccessAccounts.ps1](../scripts/04-New-EmergencyAccessAccounts.ps1).

## Prerequisites

- **User Administrator** to create the accounts and **Privileged Role Administrator** to assign their roles, or an existing authorized Global Administrator.
- The tenant's original, verified, managed `onmicrosoft.com` domain. Do not substitute a custom/federated domain or assume a newer fallback domain is the original domain.
- Two distinct, randomly generated 48-character passwords containing uppercase letters, lowercase letters, digits, and symbols, prepared with an approved offline generator and stored in a protected emergency credential vault.
- Approved phishing-resistant authentication, such as FIDO2 security keys, available for both accounts. The tenant must permit registration of the chosen method.
- An existing approved MFA method or an allowed Temporary Access Pass (TAP) bootstrap for registering the security keys. If using TAP, its authentication-method policy must already include these accounts, and a **Privileged Authentication Administrator** or authorized Global Administrator must issue it for these administrator accounts.
- An approved emergency-account monitoring and credential-lifecycle plan. Passwords, passkey setup, and recovery material must not appear in the recording.

> [!IMPORTANT]
> This is not a complete replacement for script 04. Admin-center steps cannot reproduce its per-user `passwordPolicies = DisablePasswordExpiration` setting or its Windows DPAPI-encrypted password file. Address password expiration through an approved out-of-band process before relying on these accounts for emergency access. Do not change the entire organization's expiration policy just to imitate a two-user setting.

## Create the two users

Use the following values. Replace `<initial-domain>` with the tenant's original domain, such as the lab's actual `contoso.onmicrosoft.com` value.

| Field | First account | Second account |
| --- | --- | --- |
| Username | `emergency-access-01` | `emergency-access-02` |
| Domain | `<initial-domain>` | `<initial-domain>` |
| Display name | `Emergency access - emergency-access-01` | `Emergency access - emergency-access-02` |
| Account type | Cloud-only member | Cloud-only member |
| Product license | None assigned by this procedure | None assigned by this procedure |
| Change password at first sign-in | Not required | Not required |

1. Open the **Microsoft 365 admin center**.
2. Select **Users** > **Active users**.
3. Search for both planned usernames before creating either account.
4. If either account already exists, stop and review it. Do not reset its password, assign it a new role, or create a duplicate as part of this procedure.
5. Select **Add a user**.
6. On **Set up the basics**, enter the first account's username, domain, and display name from the table.
7. Clear **Automatically create a password**.
8. Enter that account's prepared password while recording is paused.
9. Clear **Require this user to change their password when they first sign in**.
10. Select **Next**.
11. On **Assign product licenses**, select **Create user without product license**. If a location is required, use the actual lab location.
12. Select **Next**.
13. Leave **Optional settings > Roles** at the ordinary user role; assign the permanent administrator role in the next section.
14. Select **Next**.
15. Review the account identity and select **Finish adding**.
16. Close the completion pane without emailing or recording the password.
17. Repeat steps 5-16 for the second account, using its different password.

Creating an unlicensed account matches the script; it does not grant rights to use separately licensed services.

## Assign permanent Global Administrator access

Use Microsoft Entra roles, not Azure subscription access control. Both accounts need active assignments that do not depend on PIM activation during an emergency.

1. Open the **Microsoft Entra admin center** in the same tenant.
2. Select **Entra ID** > **Roles & admins**.
3. Open **Global Administrator** by selecting the role name.
4. Select **Add assignments**.
5. Select the two new emergency users.
6. Keep the assignment at tenant/directory scope, not an administrative unit.
7. If the PIM assignment wizard appears, select **Next**.
8. In that wizard, set **Assignment type** to **Active** and the assignment duration to **Permanent**. Do not select **Eligible** or a time-bound assignment.
9. Select **Add** or **Assign**, according to the wizard displayed.

If the tenant's role-assignment policy prevents permanent active assignment, stop for authorized review. A temporary eligible assignment is not an equivalent workaround.

## Bootstrap registration when an account has no MFA method

Skip this section if an approved MFA method is already available for enrollment. A password alone is not sufficient to register the first FIDO2 key. Use the approved TAP bootstrap rather than registering an employee's personal phone to an emergency account.

1. In the Entra admin center, open **Entra ID** > **Users** > **All users**.
2. Open the first emergency account as the authorized authentication administrator.
3. Open **Authentication methods**.
4. Select **Add authentication method**.
5. Select **Temporary Access Pass**.
6. Set activation to the current time.
7. Choose a short lifetime permitted by the tenant policy, such as 60 minutes.
8. Set **One-time use** to **Yes**.
9. Pause recording before generating or displaying the TAP.
10. Select **Add**.
11. Securely retain the displayed TAP for immediate use in the next section.
12. Select **OK**.

A newly issued TAP is usable only if the account is included in the tenant's TAP policy. If that prerequisite is missing, stop for an authorized authentication-policy change; do not enable TAP tenant-wide merely to complete the recording.

## Register the emergency security keys

Account creation does not enroll MFA. Conditional Access exclusions also do not exempt an account from Microsoft's mandatory administrator MFA requirements. Complete registration within 10 minutes of a single-use TAP sign-in.

1. In a separate private browser session, open [Security info](https://mysignins.microsoft.com/security-info).
2. Sign in as the first emergency account using its TAP, or complete MFA with its approved existing method.
3. Select **Add sign-in method**.
4. Under **Choose a method**, select **Passkey**.
5. Select **Next**.
6. Choose **Security key** as the storage location. Use **More options** or **Use another device** if the browser initially offers the computer or a phone instead.
7. Complete the security-key connection, PIN, and touch prompts while recording is paused.
8. Select **Done**.
9. Sign out and complete a fresh sign-in using the registered security key before relying on it for recovery.
10. If a TAP was issued, delete its entry from **Security info** once enrollment is complete.
11. Sign out and repeat the bootstrap, if needed, and registration steps for the second account.
12. Place each account's credentials and security key in approved protected storage, separate from ordinary administrator credentials.

This enrollment preparation is an additional safeguard called for by script 04's warning, not an operation performed by the script.

## Record the emergency user IDs

Use the user objects, not role-assignment IDs or authentication-method IDs.

1. Return to the Entra admin center as the lab administrator.
2. Open **Entra ID** > **Users** > **All users**.
3. Open the first emergency user's details.
4. Copy its **Object ID** into the protected lab record.
5. Repeat steps 3-4 for the second user.

Before enforcing restrictive policies, both accounts must have usable sign-in methods and an approved recovery/monitoring arrangement. The two object IDs, not their display names, are the `EmergencyAccessAccountId` equivalents used by scripts 10, 12, 16, and 18.

## Expected configuration

Both accounts are enabled cloud-only members with the exact usernames and display names above and permanent tenant-wide Global Administrator assignments. Their passwords are different and no first-sign-in password change is requested. The non-expiration flag and encrypted artifact remain the explicitly documented browser-only gaps.

Do not create an emergency-access group for the later exclusions: these procedures match the scripts' **individual user** exclusions.

## Related content

- [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
- [Add users in Microsoft 365](https://learn.microsoft.com/microsoft-365/admin/add-users/add-users)
- [Password expiration policies](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy#password-expiration-policies)
- [Assign Microsoft Entra roles in PIM](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user)
- [Bootstrap passwordless authentication with a Temporary Access Pass](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass)
- [Register a passkey with a FIDO2 security key](https://learn.microsoft.com/entra/identity/authentication/how-to-register-passkey-with-security-key)
