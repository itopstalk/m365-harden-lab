---
title: Register the optional Teams certificate application
description: Create the cloud application, certificate credential, Graph permission, and Teams directory role for the lab's optional automation identity.
ms.topic: how-to
ms.date: 10/05/2026
#customer intent: As a lab administrator, I want a narrowly authorized Teams automation identity without adding a client secret.
---

# Register the optional Teams certificate application

Create the cloud portion of the certificate-authenticated Teams application. This is optional automation setup, not a requirement for the browser-based Teams procedures or delegated execution of script 99.

**Admin tool:** [Microsoft Entra admin center](https://entra.microsoft.com).

**Script mapping:** [06-New-TeamsCertificateApplication.ps1](../scripts/06-New-TeamsCertificateApplication.ps1).

## Prerequisites

- **Cloud Application Administrator** or **Application Administrator** for app management, plus an active **Privileged Role Administrator** for Microsoft Graph application consent and the directory-role assignment, or existing authorized Global Administrator access.
- A provisioned Microsoft Teams tenant.
- A dedicated certificate prepared through an approved local certificate process, with its private key available to the Windows user who will run Teams PowerShell.
- The certificate's **public** `.cer` file and its recorded thumbprint. Do not upload a PFX or private key.
- No existing application using the planned display name. The script refuses collisions, and this procedure does not reuse an unknown identity.

> [!IMPORTANT]
> An admin center cannot create the local certificate used by script 06. To reproduce its default local setup, the certificate must have subject `CN=SecureM365 Teams Meeting Policy Automation`, RSA 3072-bit key, SHA-256 signature, a non-exportable signing key, and a 12-month lifetime in `Cert:\CurrentUser\My`. Uploading a public certificate does not install its private key on the reporting computer.

## Register the application

Use a new single-tenant application with no redirect URI or client secret.

1. Sign in to the **Microsoft Entra admin center**.
2. Open **Entra ID** > **App registrations**.
3. Select **All applications**.
4. Search for `SecureM365 Teams Meeting Policy Automation`.
5. If an application already has that name, stop and review it. Do not add credentials or permissions to it automatically.
6. Select **New registration**.
7. Enter **Name**: `SecureM365 Teams Meeting Policy Automation`.
8. Under **Supported account types**, select **Accounts in this organizational directory only**.
9. Leave **Redirect URI** blank.
10. Select **Register**.
11. On **Overview**, record the **Application (client) ID**, **Directory (tenant) ID**, and application **Object ID**.

Portal registration also creates the tenant's enterprise application/service principal. Do not create a second app registration for that identity.

## Upload the public certificate

Keep all private-key material outside the browser upload and repository.

1. In the app registration, open **Certificates & secrets**.
2. Select **Certificates**.
3. Select **Upload certificate**.
4. Choose the prepared public `.cer` file.
5. If a description is requested, enter `CN=SecureM365 Teams Meeting Policy Automation`.
6. Select **Add**.
7. Record the displayed thumbprint and expiration date alongside the application's client ID.

Do not select **New client secret**. Do not use an online certificate generator or export a private key just to complete this recording.

## Grant the one Graph application permission

The application itself needs only `Organization.Read.All` for the `*-Cs` meeting-policy cmdlets used by this lab. The setup administrator's permissions are not the application's permissions.

1. Open **API permissions**.
2. If the new registration contains the default delegated **Microsoft Graph > User.Read** permission, open its menu and select **Remove permission**.
3. Confirm that removal.
4. Select **Add a permission**.
5. Select **Microsoft Graph**.
6. Select **Application permissions**, not **Delegated permissions**.
7. Search for `Organization.Read.All`.
8. Select **Organization.Read.All**.
9. Select **Add permissions**.
10. Using the authorized consent administrator, select **Grant admin consent for <tenant>**.
11. Confirm the consent request.

The resulting permission list must contain only the intended **Microsoft Graph / Organization.Read.All / Application** permission with tenant admin consent. Do not add `User.Read.All`, `Group.ReadWrite.All`, or the **Skype and Teams Tenant Admin API**. Microsoft explicitly warns against adding that Teams API permission for this authentication path.

## Assign the Teams directory role to the application

Assign a Microsoft Entra directory role to the **service principal**, not an Azure subscription role or a role to the app's human owner.

1. Open **Entra ID** > **Enterprise apps**.
2. Open `SecureM365 Teams Meeting Policy Automation`, matching the recorded **Application ID**.
3. Record this enterprise application's **Object ID**. It is the service principal ID and differs from the app registration's object ID.
4. Open **Entra ID** > **Roles & admins**.
5. Open **Teams Communications Administrator**.
6. Select **Add assignments**.
7. Search for `SecureM365 Teams Meeting Policy Automation` and select its application/service-principal identity.
8. Keep the assignment tenant-wide.
9. If assignment type or duration choices appear, use active, permanent access, not user PIM eligibility.
10. Select **Add** or **Assign**.

Do not use **Azure portal > Subscriptions > Access control (IAM)** for this role. Do not substitute the broader Teams Administrator role merely because it is easier to find.

## Expected configuration and reporting handoff

| Setting | Value |
| --- | --- |
| Application name | `SecureM365 Teams Meeting Policy Automation` |
| Sign-in audience | Single tenant / `AzureADMyOrg` |
| Credential | Public certificate attached; no client secret |
| Graph application permission | `Organization.Read.All`, with admin consent |
| Directory role on the service principal | Teams Communications Administrator, tenant-wide |
| Local private key | Preexisting approved prerequisite; not created by this procedure |

Allow role and consent propagation. When using the optional application path in the existing scripts, supply the recorded client ID as `TeamsApplicationId` and the matching local certificate thumbprint as `TeamsCertificateThumbprint`. The private key must be accessible to that Windows user on that computer. An uploaded `.cer` alone cannot authenticate Teams PowerShell.

This does not make Microsoft Graph or Exchange connections certificate-authenticated. It only replaces the Teams connection. Do not rerun script 06 against the manually created application; its collision protection is expected to stop.

## Related content

- [Application-based authentication in Teams PowerShell](https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication)
- [Register an application and upload a certificate](https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal)
- [Assign Microsoft Entra roles](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal)
