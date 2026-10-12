# Microsoft 365 Tenant Security Controls

Implement the following security controls in the assigned Microsoft 365 tenant. Policies must be enabled and enforced, not left in report-only mode. Any exclusions, including emergency-access accounts, must be agreed with the assessor.

1. **Multifactor authentication for administrative roles**

   Require multifactor authentication (MFA) for users holding administrative roles. Apply the requirement to directory roles or cover administrators through an All-users MFA policy. MFA must be mandatory, not an alternative to satisfying a different access requirement.

2. **Multifactor authentication for all users**

   Apply a mandatory MFA requirement to **All users**, covering **All resources**, subject to approved exclusions.

3. **Block legacy authentication**

   Block legacy-authentication sign-ins for **All users** across **All resources**. Cover both **Exchange ActiveSync clients** and **Other clients** using legacy authentication, subject to approved exclusions.

4. **MFA for elevated sign-in risk**

   Apply a sign-in risk policy to **All users** across **All resources**. Require MFA when sign-in risk is **Medium or High**. Require reauthentication **Every time**, covering both primary and multifactor authentication.

5. **Remediation for high user risk**

   Apply a user-risk policy to **All users** across **All resources**. When user risk is **High**, require both MFA and risk remediation. Use either adaptive risk remediation or a secure password-change requirement, not both remediation controls together. Require reauthentication **Every time**, covering both primary and multifactor authentication.

6. **Prevent ordinary-user application consent**

   Prevent ordinary users from granting new consent to applications that access organizational data on their behalf. This includes limited self-consent for verified publishers or low-risk permissions; ordinary-user self-consent must be disabled.

7. **Invited-participant Teams lobby bypass**

   Configure the **Global (Org-wide default)** Teams meeting policy so that **Who can bypass the lobby** defaults to **People who were invited**.

8. **Organizer-only default Teams presenters**

   Configure the **Global (Org-wide default)** Teams meeting policy so that **Who can present** defaults to **Only organizers and co-organizers**. Other participants must join as attendees by default.

9. **Prevent anonymous Teams meeting join**

   Disable **Anonymous users can join a meeting** in the **Global (Org-wide default)** Teams meeting policy. Requiring anonymous participants to wait in the lobby is not equivalent to preventing them from joining.

10. **Self-service password reset for all users**

    Set **Self service password reset enabled** to **All** for the tenant. Enabling reset only for selected users or a selected group does not meet this requirement.
