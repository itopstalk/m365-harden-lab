---
title: Set invited-user lobby bypass in the Global Teams meeting policy
description: Configure People who were invited as the Global policy's default lobby-bypass setting.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want invited participants to bypass the lobby by default while matching the Global policy checked by the scripts.
---

# Set invited-user lobby bypass in the Global Teams meeting policy

Set **Who can bypass the lobby** to **People who were invited** in the Global meeting policy. This is a default for organizers governed by that policy, not an immutable setting for every meeting in the tenant.

**Admin tool:** [Microsoft Teams admin center](https://admin.teams.microsoft.com).

**Script mapping:** [40-Set-TeamsInvitedUsersLobbyPolicy.ps1](../scripts/40-Set-TeamsInvitedUsersLobbyPolicy.ps1).

## Prerequisites

- An active **Teams Communications Administrator** role, or existing Teams Administrator coverage.
- Microsoft Teams provisioned for the tenant and administrative access to meeting policies.
- Approval to change the shared Global policy. Custom policies and their user/group assignments are outside this task.

## Change the Global lobby default

Do not create a new policy or edit a meeting's individual options.

1. Sign in to the **Microsoft Teams admin center**.
2. Expand **Meetings**.
3. Select **Meeting policies**.
4. Open **Global (Org-wide default)**.
5. Locate **Meeting join & lobby**.
6. Set **Who can bypass the lobby** to **People who were invited**.
7. Leave the other settings unchanged.
8. Select **Save**.

If the Global policy is missing or inaccessible, stop for access/provisioning review. A similarly named custom policy is not a substitute.

## Expected configuration

| Setting | Value |
| --- | --- |
| Policy | Global (Org-wide default) / `Global` |
| Who can bypass the lobby | People who were invited |
| PowerShell property | `AutoAdmittedUsers = InvitedUsers` |

Invitations forwarded to eligible participants can count as invitations; this setting is not restricted to only people directly invited by the original organizer. Dial-in bypass and who can admit people from the lobby are separate controls that this script does not change.

Organizers can change the default through meeting options unless another feature enforces it. Do not add a Teams Premium template or sensitivity label merely to lock the value; that would go beyond script 40.

Allow up to 24 hours for policy changes to take effect. The final report reads **Global**, not individual meetings or effective custom-policy assignments.

## Related content

- [Manage lobby options in Teams](https://learn.microsoft.com/microsoftteams/who-can-bypass-meeting-lobby)
- [Manage Teams meeting policies](https://learn.microsoft.com/microsoftteams/meeting-policies-overview)
