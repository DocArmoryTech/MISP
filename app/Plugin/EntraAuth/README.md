# Microsoft Entra ID Authentication Plugin for MISP

This plugin enables seamless Single Sign-On (SSO) and automatic user provisioning for [MISP (Malware Information Sharing Platform)](https://github.com/MISP/MISP) using **Microsoft Entra ID** (formerly Azure Active Directory) via OAuth 2.0 and the Microsoft Graph API.

## Features

- **Automated User Provisioning:** Automatically creates a local MISP account when an authorized Entra user logs in for the first time.
- **Dynamic Role Mapping:** Maps Entra ID Group memberships directly to internal MISP Roles (`Site Admin`, `Org Admin`, etc.).
- **Organization Synchronization:** Maps external organization parameters or claims to local MISP organizations natively.
- **Adaptive Scopes:** Dynamically restricts or expands requested OAuth permissions (`User.Read` vs. `GroupMember.Read.All`) based on whether group mapping is active, featuring explicit override options.
- **Enterprise Proxy Support:** Fully integrates with MISP's internal forward-proxy configurations.


## 1. Microsoft Entra ID App Registration Configuration

1. Go to the **Microsoft Entra Admin Center** and select **App registrations** > **New registration**.
2. Provide a descriptive name, choose **Web** as the platform type, and set the **Redirect URI** to your MISP instance login endpoint:
   ```text
   [https://misp.yourdomain.com/users/login](https://misp.yourdomain.com/users/login)
   ```

   *Note: The Redirect URI specified here must match your configuration array entry exactly.*

3. From the application **Overview** page, record the following values:

   * **Application (client) ID**
   * **Directory (tenant) ID**


4. Navigate to **Certificates & secrets** > **Client secrets** > **New client secret**. Select an expiration policy matching your internal compliance criteria.
5. **Immediately copy the Value** from the client secret row. 

   *Note: This value becomes hidden after leaving the page.*

### API Permissions (Conditional)

If you plan to map internal MISP roles based on Entra security group memberships, you must register Graph API directory authorizations:

1. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated permissions**.
2. Search for and select `GroupMember.Read.All` (or `Group.Read.All`).
3. Once added, click **Grant admin consent for [Your Tenant]** to authorize the permission across your organization.
4. Ensure your designated enterprise directories or security groups have been created inside Entra ID and capture their exact names:

### Mapping to `claims`
By default, standard attributes like `userPrincipalName` or `mail` are included in the baseline identity token. However, mapping custom organization details or metadata-such as your `organisation_property` (e.g., `organization`) and `organisation_uuid_property` (e.g., `organization_uuid`)-requires exposing these claims via the App Registration's **Token Configuration** or **Enterprise Application Attributes & Claims** engine.

Depending on how your enterprise tracks organization metadata in Entra ID, choose one of the two methods below to expose these claims to the plugin.

#### Method A: Using Standard Directory Attributes (Most Common)

If you store the organization name in a default Microsoft Entra ID profile field (such as the native `Company name` or `Department` attribute), you can map it directly into the token.

1. Sign in to the **Microsoft Entra Admin Center**.
2. Navigate to **Identity** > **Applications** > **App registrations**, and select your MISP application.
3. On the left sidebar under *Manage*, click on **Token configuration**.
4. Click **Add optional claim**.
5. In the drawer that appears on the right:
   * Select **ID** as the token type.
   * Look through the list of standard claims. If you are using the native directory fields, check **`companyname`** (maps to `organization` name) or **`tenantid`** (if your MISP organization maps exactly to your Microsoft Directory Tenant UUID).
6. Click **Add**.
7. If prompted, check the box to **Turn on the Microsoft Graph profile permission** (this ensures the scope matches what the application requires to parse it) and click **Save**.

   *Note: If you use `companyname`, update your MISP `config.php` to target it:*

   ```php
   'organisation_property' => 'companyname',
   ```

#### Method B: Using Custom Claims via Enterprise Applications (For UUIDs & Extension Attributes)

If your organization requires mapping a specific custom schema attribute (like a dedicated corporate `organization_uuid` or an `extension_attribute` synced from on-premises Active Directory), you must define a custom claim transformation.

1. In the **Microsoft Entra Admin Center**, navigate to **Identity** > **Applications** > **Enterprise applications** (instead of *App registrations*).
2. Search for and select your MISP application service principal.
3. Under *Manage* in the left sidebar, click **Single sign-on**.
4. In the main pane, find the **Attributes & Claims** section box and click **Edit**.
5. To expose a custom property, click **Add new claim**.
6. Configure the claim details:
   * **Name:** Enter the exact string key expected by your MISP plugin config (e.g., `organization` or `organization_uuid`).
   * **Namespace:** Leave this blank to keep the claim short and clean (e.g., `organization` instead of `http://schemas.xmlsoap.org/.../organization`).
   * **Source:** Select **Attribute**.
   * **Source attribute:** Open the dropdown and search for the profile property holding your data.
   * For names: Choose `user.companyname` or `user.department`.
   * For synced on-premises custom attributes: Choose `user.onpremisesextensionattribute1` through `15`.
7. Click **Save**.

#### Method C: emulating claims via App Roles (Alternative for static environments)

If your Entra tenant doesn't have custom extension schemas enabled but you still need to pass a static Organization identifier based on user groups, you can use **App Roles**.

1. Go back to **App registrations** and choose your MISP app.
2. Click **App roles** > **Create app role**.
3. Define the role:
   * **Display name:** e.g., `External Org - Cert Team`
   * **Allowed member types:** Both (Users/Groups)
   * **Value:** This must be the exact text name or UUID of the MISP organization you want to assign (e.g., `CERT-Team`).


4. Once created, assign users or groups to this App Role under **Enterprise Applications**.
5. In your Token Configuration, ensure the `roles` claim is added to your ID token. You can then map `roles` as your organizational property:
   ```php
   'organisation_property' => 'roles',
   ```

## 2. Plugin Installation & Activation

1. Access your MISP host over SSH and switch context to the `misp` system identity:
   ```bash
   su - misp
   ```

2. **Crucial:** Always back up your operational configurations prior to editing database arrays:
   ```bash
   cp /var/www/MISP/app/Config/config.php /var/www/MISP/app/Config/config.orig.php
   ```

3. Open `/var/www/MISP/app/Config/config.php` inside a text editor:
   ```bash
   nano /var/www/MISP/app/Config/config.php
   ```
4. Find the global `'Security'` context parameter block and register the Component class array mapping:
   ```php
   'auth' => array(
       0 => 'EntraAuth.EntraAuthenticate',
   ),
   ```

## 3. Configuration Parameters

Append the following configuration schema near the bottom of your `/var/www/MISP/app/Config/config.php` script:
```php
'EntraAuth' => array(
    'client_id'                  => 'YOUR_APPLICATION_CLIENT_ID',            // [Required] Application (client) ID from Entra
    'entra_tenant'               => 'YOUR_DIRECTORY_TENANT_ID',              // [Required] Directory (tenant) ID or "common"
    'client_secret'              => 'YOUR_CLIENT_SECRET_VALUE',              // [Required] Client Secret Value
    'redirect_uri'               => 'https://misp.mydomain.com/users/login', // [Required] Must match Entra ID registration exactly
    'auth_provider'              => 'https://login.microsoftonline.com/',    // Authentication base URL endpoint
    'auth_provider_user'         => 'https://graph.microsoft.com/',          // Microsoft Graph API gateway endpoint
    'auth_property_name'         => 'userPrincipalName',                     // Principal email handle property (e.g., 'mail' or 'userPrincipalName')
    'organisation_property'      => 'organization',                          // Profile token key targeting target organization name
    'organisation_uuid_property' => 'organization_uuid',                     // Optional profile token key specifying target organization UUID
    'default_org'                => 'External Users',                        // Fallback Organization (Matches local database ID, Name, or UUID)
    'check_entra_groups'         => true,                                    // Enforce group validation checks against role mapping requirements
    'role_mapper'                => array(                                   // [Preferred] Top-down evaluation mapping: Entra Group -> MISP Role Name/ID
        'Misp Site Admins' => 'Site Admin',
        'Misp Org Admins'  => 'Org Admin',
        'Misp Users'       => 'User',
    ),
    'update_user_role'           => true,                              // Overwrite/Sync local user roles during subsequent authorization handshakes
    'update_user_org'            => true,                              // Overwrite/Sync local user organizations during subsequent handshakes
    
    // Adaptive Scope Override (Optional)
    // If left unset, automatically evaluates to "User.Read" or "User.Read GroupMember.Read.All" depending on 'check_entra_groups'.
    // 'scope'                      => 'User.Read GroupMember.Read.All',
),
```

### Legacy Configuration Parameters (Fallback)

If your legacy structural configuration relies on the old hardcoded role properties, the plugin will implicitly generate a mapping fallback:

* `misp_user`
* `misp_orgadmin`
* `misp_siteadmin`
   
   *Note: Transitioning explicit parameters over to the unified structured `role_mapper` array dictionary is highly encouraged.*


## 4. Production Security Hardening

When offloading identity management workflows directly to Microsoft Entra ID, local credentials should be severely restricted to protect against credential bypass risks.

1. When adding or enrolling new accounts locally within the MISP administration pane, ensure the **"Send credentials automatically"** setting remains **unchecked**.
2. Apply the following restrictive configurations to your global `config.php` structure to turn off local user self-management modifications:
   ```php
   'MISP' => array(
       'disableUserSelfManagement'     => true, // Removes profile modifications and token regeneration access
       'disable_user_login_change'     => true, // Restricts user identity/email tracking adjustments to Site Admins
       'disable_user_password_change'  => true, // Completely blocks local user password changes
   ),
   ```

## Troubleshooting

### TLS Server Certificate Verification Failure (`CakeSocket.php`)

**Symptom:** Logs emit errors detailing validation path failures:
```text
error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed in [/var/www/MISP/app/Lib/cakephp/lib/Cake/Network/CakeSocket.php, line 504]
```

**Root Cause:** This occurs when your corporate firewall topology enforces deep packet TLS inspection proxies, causing remote verification requests aimed at Microsoft’s web infrastructure endpoints to fail trust challenges.

**Resolution:** Append your enterprise root or inspection proxy CA certificates bundle directly onto the embedded CakePHP validation root file:
```bash
cat /etc/pki/ca-trust/corporate.pem >> /var/www/MISP/app/Lib/cakephp/lib/Cake/Config/cacert.pem
```

*(Or target your custom system-configured `ca_path` variable file destination explicitly)*.