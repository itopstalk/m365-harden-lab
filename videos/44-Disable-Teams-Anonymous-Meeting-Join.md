---
title: Disable anonymous meeting join in the Global Teams meeting policy
description: Turn off Anonymous users can join a meeting on the Global meeting policy without changing other collaboration settings.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want anonymous join disabled for organizers governed by the Global policy.
---

# Disable anonymous meeting join in the Global Teams meeting policy

Turn off anonymous meeting join in **Global (Org-wide default)**. This matches the policy property that script 44 changes and script 99 reads.

**Admin tool:** [Microsoft Teams admin center](https://admin.teams.microsoft.com).

**Script mapping:** [44-Disable-TeamsAnonymousMeetingJoin.ps1](../scripts/44-Disable-TeamsAnonymousMeetingJoin.ps1).

## Prerequisites

- An active **Teams Communications Administrator** role, or existing Teams Administrator coverage.
- Microsoft Teams provisioned and access to meeting policies.
- Approval for the impact on participants who cannot join with a verifiable identity.

## Disable anonymous join in Global

Use **Meeting policies**, not the separate organization-wide **Meeting settings** page.

1. Sign in to the **Microsoft Teams admin center**.
2. Expand **Meetings**.
3. Select **Meeting policies**.
4. Open **Global (Org-wide default)**.
5. Locate **Meeting join & lobby**.
6. Set **Anonymous users can join a meeting** to **Off**.
7. Leave the other settings unchanged.
8. Select **Save**.

If the Global policy is missing or inaccessible, stop for access/provisioning review.

## Expected configuration

| Setting | Value |
| --- | --- |
| Policy | Global (Org-wide default) / `Global` |
| Anonymous users can join a meeting | Off |
| PowerShell property | `AllowAnonymousUsersToJoinMeeting = false` |

The separate **Anonymous users and dial-in callers can start a meeting** setting is not the required control. Neither is forcing anonymous participants to wait in the lobby: that still permits joining after admission.

An organization-wide anonymous-join setting, if shown under **Meetings > Meeting settings**, can also affect behavior. Do not change it in place of this Global policy property; script 99 does not use it as substitute evidence.

Leave Teams guest access, external access, dial-in settings, custom meeting policies, and policy assignments unchanged. Authenticated guests are not automatically the same as anonymous participants. The scope is organizers whose effective meeting policy is Global, not every custom-policy organizer in the tenant.

Allow up to 24 hours for policy propagation.

## Related content

- [Manage lobby and anonymous-join policies](https://learn.microsoft.com/microsoftteams/who-can-bypass-meeting-lobby)
- [Manage Teams meeting policies](https://learn.microsoft.com/microsoftteams/meeting-policies-overview)
