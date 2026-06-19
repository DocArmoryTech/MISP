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
5. **Immediately copy the Value** from the client secret row. *(This value becomes hidden after leaving the page)*.

### API Permissions (Conditional)

If you plan to map internal MISP roles based on Entra security group memberships, you must register Graph API directory authorizations:

1. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated permissions**.
2. Search for and select `GroupMember.Read.All` (or `Group.Read.All`).
3. Once added, click **Grant admin consent for [Your Tenant]** to authorize the permission across your organization.
4. Ensure your designated enterprise directories or security groups have been created inside Entra ID and capture their exact names:


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