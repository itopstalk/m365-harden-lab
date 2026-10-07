---
title: Remove the optional Teams certificate application
description: Retire the dedicated Teams automation identity and its cloud authorization without undoing the Teams meeting policies.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want to revoke a retired Teams automation identity without deleting the wrong application or changing meeting settings.
---

# Remove the optional Teams certificate application

Retire the cloud identity created by procedure 06. This is optional cleanup after automation is no longer needed, not a step in the main hardening sequence.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [07-Remove-TeamsCertificateApplication.ps1](../scripts/07-Remove-TeamsCertificateApplication.ps1).

## Prerequisites

- An active **Privileged Role Administrator** for directory-role removal and **Cloud Application Administrator** or **Application Administrator** for application deletion, or existing authorized Global Administrator access.
- The recorded client/application ID, app registration object ID, service principal object ID, and certificate thumbprint.
- Confirmation that no required scheduled job or reporting process still uses this identity.
- A dedicated application from procedure 06. Unexpected owners, permissions, or role assignments require review before deletion.

> [!WARNING]
> Deleting this identity stops its future Teams application-authentication use. Do not run this procedure before a final report that still depends on its certificate. Use delegated Teams sign-in or an already-prepared replacement instead.

## Remove directory-role authorization

Match identifiers, not only the display name, before removing a grant.

1. Sign in to the **Microsoft Entra admin center** in the application's recorded tenant.
2. Open **Entra ID** > **Enterprise apps**.
3. Locate the application by its recorded **Application ID**.
4. Open it and match its **Object ID** to the recorded service principal ID.
5. Open **Entra ID** > **Roles & admins**.
6. Open **Teams Communications Administrator**.
7. Find the assignment belonging to that exact application/service principal.
8. Select the assignment and select **Remove**.
9. Confirm the removal.

If the application acquired additional directory roles after setup, review and remove those assignments to this exact service principal as well. Script 07 removes all of that principal's directory-role assignments, not roles belonging to its owners or other applications.

## Delete the enterprise application and app registration

Deleting the service principal removes its application-permission grants. Merely removing a permission from an app registration's requested-permissions list is not the same as revoking a granted permission.

1. Return to **Entra ID** > **Enterprise apps**.
2. Open the enterprise application with the recorded **Application ID** and service principal **Object ID**.
3. Open **Properties**.
4. Select **Delete**.
5. Confirm deletion of that enterprise application.
6. Open **Entra ID** > **App registrations** > **All applications**.
7. Locate the app registration using the recorded **Application (client) ID**.
8. If it remains, open it and match its application **Object ID** to the recorded registration object ID.
9. Select **Delete**.
10. Acknowledge the deletion consequences and confirm deletion.

If a cloud object was already removed, skip only its corresponding deletion after confirming the identifier. Do not delete a different object with a similar name. Do not permanently purge unrelated deleted applications.

## Expected configuration and local cleanup boundary

The dedicated service principal, app registration, application-permission grants, and directory-role assignments are removed. The Global Teams meeting policy settings from procedures 40, 42, and 44 remain unchanged.

This reproduces the cloud cleanup outcome of script 07. It does **not** reproduce the optional `RemoveLocalCertificate` operation: a browser cannot delete the certificate or private key in `Cert:\CurrentUser\My`. Arrange separate approved local cleanup of that exact thumbprint if required. Do not assume deleting the uploaded certificate or app deletes local private-key material.

The final report can still run using delegated Teams authentication. Do not continue supplying the deleted application's client ID to it.

## Related content

- [Teams application-based authentication](https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication)
- [Assign and manage Microsoft Entra roles](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal)
- [Application and service principal objects](https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals)
