---
title: Set organizer-only default presenters in the Global Teams meeting policy
description: Configure Only organizers and co-organizers as the Global policy's default Who can present setting.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want presenters limited by default to organizers and co-organizers while preserving the script's policy scope.
---

# Set organizer-only default presenters in the Global Teams meeting policy

Set the Global meeting policy's **Who can present** default to **Only organizers and co-organizers**. This corresponds to the script's `OrganizerOnlyUserOverride` value.

**Admin tool:** [Microsoft Teams admin center](https://admin.teams.microsoft.com).

**Script mapping:** [42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1](../scripts/42-Set-TeamsOrganizerOnlyPresenterPolicy.ps1).

## Prerequisites

- An active **Teams Communications Administrator** role, or existing Teams Administrator coverage.
- Microsoft Teams provisioned and access to meeting policies.
- Approval to change the shared Global policy without changing custom policies or assignments.

## Change the Global presenter default

Edit the meeting policy, not a meeting invitation, webinar role list, or live-event policy.

1. Sign in to the **Microsoft Teams admin center**.
2. Expand **Meetings**.
3. Select **Meeting policies**.
4. Open **Global (Org-wide default)**.
5. Locate **Content sharing**.
6. Set **Who can present** to **Only organizers and co-organizers**.
7. Leave **Participants can give or request control**, **External participants can give or request control**, and the other settings unchanged.
8. Select **Save**.

If the Global policy is unavailable, stop rather than creating or modifying a custom policy in its place.

## Expected configuration

| Setting | Value |
| --- | --- |
| Policy | Global (Org-wide default) / `Global` |
| Who can present | Only organizers and co-organizers |
| PowerShell property | `DesignatedPresenterRoleMode = OrganizerOnlyUserOverride` |

The current portal label includes co-organizers even though the script's name says organizer-only. Other participants join as attendees by default.

The `UserOverride` behavior matters: organizers can still change this choice in their meeting options. This is not a locked-down presentation prohibition, and **People in my org and guests** is not equivalent.

Do not change policy assignments or add sensitivity labels/templates as part of this procedure. Allow up to 24 hours for Teams policy propagation.

## Related content

- [Manage who can present in Teams meetings](https://learn.microsoft.com/microsoftteams/meeting-who-present-request-control)
- [Manage Teams meeting policies](https://learn.microsoft.com/microsoftteams/meeting-policies-overview)
