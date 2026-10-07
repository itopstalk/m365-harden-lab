---
title: Assign the lab administrator's missing roles
description: Supply the active tenant-wide role coverage used by the Microsoft 365 hardening scripts without granting Global Administrator.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want the necessary service roles so that I can configure and report on the lab.
---

# Assign the lab administrator's missing roles

Assign only the missing built-in roles needed by the lab administrator. This covers the role-remediation part of script 05, not its connection, module, licensing, or delegated-consent checks.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [05-Verify-Admin-Permissions.ps1](../scripts/05-Verify-Admin-Permissions.ps1).

## Prerequisites

- An existing, active, tenant-wide **Privileged Role Administrator** or **Global Administrator** authorized to assign roles.
- The identity of the lab administrator who would run script 05. Do not substitute an emergency account or the Teams application as the target.
- Approval for any new permanent active assignments. They match the script's lab behavior, not a general production privilege recommendation.
- Activation of any existing PIM-eligible roles before deciding that permanent assignments are missing.

## Identify the missing role coverage

The script accepts appropriate broader roles and existing active role-assignable group membership. It never assigns Global Administrator. An existing active tenant-wide Global Administrator already satisfies its role coverage and does not need duplicate grants.

| Capability | Role the script adds when needed | Existing coverage that can avoid that grant |
| --- | --- | --- |
| Manage Conditional Access | Conditional Access Administrator | Security Administrator |
| Create emergency users; configure SSPR Properties | User Administrator | Directory Writers covers user creation only; Authentication Policy Administrator covers SSPR Properties only |
| Assign roles and change consent through Graph | Privileged Role Administrator | Existing Global Administrator; assignment authority must already exist |
| Read authentication registration reports | Security Reader | Reports Reader, Security Administrator, or Global Reader |
| Read the default app management policy for scripts 62/69 | Global Reader | Existing Global Administrator |
| Manage Teams meeting policies | Teams Communications Administrator | Teams Administrator |

Security Reader also covers the Secure Score reads. The script evaluates these capabilities in order, so it can add both Security Reader and Global Reader when neither was present. Preserve existing broader coverage rather than adding every role in the table automatically.

1. Sign in to the **Microsoft Entra admin center**.
2. Select **Entra ID** > **Users** > **All users**.
3. Open the lab administrator's account.
4. Open **Assigned roles**.
5. Compare active, tenant-wide coverage with the table. Account for active group-based assignments; PIM eligibility alone is not active access.
6. If custom or scoped roles make coverage unclear, stop for an authorized role review rather than assuming that more privilege is required.

This review chooses which assignments to create; it is not a separate validation recording.

## Assign each missing role

Repeat these steps only for a role not already covered.

1. Select **Entra ID** > **Roles & admins**.
2. Open the required role by selecting its name.
3. Select **Add assignments**.
4. Search for the lab administrator by sign-in name.
5. Select that administrator.
6. Keep the scope at the entire directory/tenant.
7. If the PIM assignment wizard appears, select **Next**.
8. In that wizard, choose **Active** and **Permanent** to reproduce the script's new-assignment behavior.
9. Select **Add** or **Assign**.
10. Repeat for each remaining missing role.
11. Allow assignments to propagate before signing out and signing back in to the affected admin portals.

If permanent active assignments are disallowed by governance policy, do not change the policy merely to complete a recording. An approved PIM activation can provide operational access, but is a deliberate difference from a new permanent assignment.

## Expected configuration and portal differences

The intended lab administrator has the required active tenant-wide role coverage. No Global Administrator role, custom role, group membership, or service policy was added by this procedure.

The **user-consent portal** currently requires an existing **Global Administrator**, unlike script 30's Graph path using Privileged Role Administrator. Use that authorized identity for procedure 30; do not treat this guide as authorization to grant Global Administrator to the lab user.

The optional certificate-application guide also identifies its application-management and admin-consent permissions separately. Directory roles do not install modules, assign product licenses, grant delegated Graph scopes, or establish a Teams session.

## Related content

- [Assign Microsoft Entra roles](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal)
- [Assign roles in Privileged Identity Management](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user)
- [Teams administrator roles](https://learn.microsoft.com/microsoftteams/using-admin-roles)
- [Configure user consent](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
