<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('RandomTool', 'Tools');
App::uses('HttpSocket', 'Network/Http');
App::uses('CakeSession', 'Model/Datasource');

if (session_status() == PHP_SESSION_NONE) {
	session_start();
}

class EntraAuthenticateAuthenticate extends BaseAuthenticate
{
	/**
	 * Session key used for Entra OAuth state verification.
	 *
	 * @var string
	 */
	protected $oauth_state_session_key = 'entra_oauth_state';


	/**
	 * Holds the application ID
	 *
	 * @var string
	 */
	protected $client_id;

	/**
	 * Microsoft Entra tenant ID. With multitenant apps you can use "common" as tenant ID,
	 * but using a specific tenant endpoint is recommended when possible.
	 *
	 * @var string
	 */
	protected $entra_tenant;

	/**
	 * Client Secret, remember that this expires someday unless you haven't set it not to do so
	 *
	 * @var string
	 */
	protected $client_secret;

	/**
	 * Redirect URI
	 *
	 * @var string
	 */
	protected $redirect_uri;

	/**
	 * Provider authentication URL
	 *
	 * @var string
	 */
	protected $auth_provider;

	/**
	 * Provider URL for additional user details
	 *
	 * @var string
	 */
	protected $auth_provider_user;

	/**
	 * Name of the property to use for authentication.
	 *
	 * @var string
	 */
	protected $auth_property_name;

	/**
	 * Determined or overridden OAuth scopes.
	 *
	 * @var string
	 */
	protected $scope;

	/**
	 * Name of the property that contains the organisation name.
	 *
	 * @var string
	 */
	protected $organisation_property;

	/**
	 * Name of the property that contains the organisation UUID.
	 *
	 * @var string
	 */
	protected $organisation_uuid_property;

	/**
	 * Optional default organisation when no valid org claim is provided.
	 *
	 * @var string|int
	 */
	protected $default_org;

	/**
	 * Mapping from Entra groups to MISP roles.
	 *
	 * @var array
	 */
	protected $role_mapper;

	/**
	 * Should existing user role be updated on login.
	 *
	 * @var bool
	 */
	protected $update_user_role;

	/**
	 * Should existing user organisation be updated on login.
	 *
	 * @var bool
	 */
	protected $update_user_org;

	/**
	 * Flag that indicates if we need to check Entra groups for defining MISP access
	 *
	 * @var bool
	 */
	protected $check_entra_groups;

	/**
	 * Entra group MISP user
	 *
	 * @var string
	 */
	protected $misp_user;

	/**
	 * Entra group MISP org admin
	 *
	 * @var string
	 */
	protected $misp_orgadmin;

	/**
	 * Entra group MISP siteadmin
	 *
	 * @var string
	 */
	protected $misp_siteadmin;

	/**
	 * Current response object used for redirects in auth flow.
	 *
	 * @var CakeResponse|null
	 */
	protected $response;

	public function __construct()
	{
		$this->client_id = Configure::read('EntraAuth.client_id');
		$this->entra_tenant =  Configure::read('EntraAuth.entra_tenant');
		$this->client_secret =  Configure::read('EntraAuth.client_secret');
		$this->redirect_uri =  Configure::read('EntraAuth.redirect_uri');
		$this->auth_provider =  Configure::read('EntraAuth.auth_provider');
		$this->auth_provider_user =  Configure::read('EntraAuth.auth_provider_user');
		
		// Resolve scopes dynamically, or fall back to an explicit config override
		$configScope = Configure::read('EntraAuth.scope');
		if (!empty($configScope)) {
			$this->scope = $configScope;
		} else {
			$scopes = ['User.Read'];
			// If group checks or custom group role mappings are used, request group read permissions
			if ($this->check_entra_groups || !empty($this->role_mapper)) {
				$scopes[] = 'GroupMember.Read.All';
			}
			$this->scope = implode(' ', $scopes);
		}
		
		$this->misp_user =  Configure::read('EntraAuth.misp_user');
		$this->misp_orgadmin =  Configure::read('EntraAuth.misp_orgadmin');
		$this->misp_siteadmin =  Configure::read('EntraAuth.misp_siteadmin');
		$this->check_entra_groups =  Configure::read('EntraAuth.check_entra_groups');
		$this->auth_property_name =  Configure::read('EntraAuth.auth_property_name') ?? 'userPrincipalName';
		$this->organisation_property = Configure::read('EntraAuth.organisation_property') ?? 'organization';
		$this->organisation_uuid_property = Configure::read('EntraAuth.organisation_uuid_property') ?? 'organization_uuid';
		$this->default_org = Configure::read('EntraAuth.default_org');
		$this->role_mapper = Configure::read('EntraAuth.role_mapper') ?? [];
		$this->update_user_role = Configure::read('EntraAuth.update_user_role');
		if ($this->update_user_role === null) {
			$this->update_user_role = true;
		}
		$this->update_user_org = Configure::read('EntraAuth.update_user_org');
		if ($this->update_user_org === null) {
			$this->update_user_org = true;
		}

		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();

		$this->settings['fields'] = ['username' => 'email'];
	}

	/**
	 * Log to MISP and Cake
	 * 
	 * @param string $level			Log level
	 * @param string $logmessage	Message to log
	 * @return bool result of the log action
	 */
	private function _log($level, $logmessage)
	{
		$log = [
			'org' => 'SYSTEM',
			'model' => 'User',
			'model_id' => 0,
			'email' => false,
			'action' => 'auth',
			'title' => $logmessage
		];
		$this->Log->saveOrFailSilently($log);
		CakeLog::write($level, $logmessage);

		return true;
	}

	/**
	 * Log non 200-ish HTTP responses
	 * 
	 * @param string 				$level			Log level
	 * @param string 				$url			Requested URL
	 * @param HttpSocketResponse 	$response		HTTP response
	 * @return bool result of the log action
	 */
	private function _logHttpError(string $level, string $url, HttpSocketResponse $response)
	{
		$this->_log($level, "POST request to url: {$url} returned HTTP code: {$response->code} with response body: {$response->body}");

		return true;
	}

	/**
	 * Find the user to authenticate with
	 * 
	 * @param CakeRequest $request The request that contains login information.
	 * @return mixed False on login failure. An array of User data on success.
	 */
	public function getUser(CakeRequest $request)
	{
		// we only proceed if called with a request to authenticate via Entra ID
		if (array_key_exists('EntraID', $request->query) and $request->query['EntraID'] == 'enable') {
			$user = $this->_getUserEntra($request);
			return $user;
		} elseif (array_key_exists('code', $request->query))  // in the Entra flow
		{
			$user = $this->_getUserEntra($request);
			return $user;
		}
		return false;
	}

	/**
	 * Authenticate
	 * 
	 * @param CakeRequest $request The request that contains login information.
	 * @param CakeResponse $response Unused response object.
	 * @return mixed False on login failure. An array of User data on success.
	 */
	public function authenticate(CakeRequest $request, CakeResponse $response)
	{
		$this->response = $response;
		return $this->getUser($request);
	}

	/**
	 * Get the Entra-authenticated user
	 * 
	 * @param CakeRequest $request The request that contains login information.
	 * @return mixed False on login failure. An array of User data on success.
	 */
	private function _getUserEntra(CakeRequest $request)
	{
		if (!headers_sent()) {
			if (!isset($request->query['code']) and !isset($request->query['error'])) {
				try {
					$state = RandomTool::random_str(true, 64);
				} catch (Exception $e) {
					$this->_log('warning', 'Failed to generate Entra OAuth state.');
					$this->_log('debug', 'State generation error: ' . $e->getMessage());
					return false;
				}
				CakeSession::write($this->oauth_state_session_key, $state);

				$url = $this->auth_provider . $this->entra_tenant . "/oauth2/v2.0/authorize?";
				$url .= "state=" . urlencode($state);
				$url .= "&scope=" . urlencode($this->scope);
				$url .= "&response_type=code";
				$url .= "&approval_prompt=auto";
				$url .= "&client_id=" . $this->client_id;
				$url .= "&redirect_uri=" . urlencode($this->redirect_uri);
				if ($this->response instanceof CakeResponse) {
					$this->response->statusCode(302);
					$this->response->header('Location', $url);
				} else {
					header("Location: " . $url);
				}
				$this->_log("info", "Redirect to Entra for authentication.");
				return false;

			} elseif (isset($request->query['error'])) {  //Second load of this page begins, but hopefully we end up to the next elseif section...
				$errorQuery = array_intersect_key($request->query, array_flip(['error', 'error_description', 'error_codes', 'timestamp', 'trace_id', 'correlation_id']));
				$this->_log("warning", "Return from Entra redirect. Error received at the beginning of second stage. Query: " . http_build_query($errorQuery, '', '  -  '));
				return false;
			} elseif (isset($request->query['state'])) {
				$stateFromRequest = $request->query['state'];
				if (!is_string($stateFromRequest) || $stateFromRequest === '') {
					$this->_log('warning', 'Entra OAuth callback contained an invalid state parameter.');
					return false;
				}

				$codeFromRequest = isset($request->query['code']) ? $request->query['code'] : null;
				if (!is_string($codeFromRequest) || $codeFromRequest === '') {
					$this->_log('warning', 'Entra OAuth callback contained an invalid authorization code.');
					return false;
				}

				$storedState = CakeSession::read($this->oauth_state_session_key);
				CakeSession::delete($this->oauth_state_session_key);

				if (!is_string($storedState) || $storedState === '') {
					// No (or expired) state in session - most commonly caused by
					// starting the login flow in two tabs/windows, where completing
					// one invalidates the state stored for the other, or by the
					// session expiring while the user was at the Entra login page.
					$this->_log('warning', 'Entra OAuth state missing or expired in session.');
					return false;
				}

				if (!hash_equals($storedState, $stateFromRequest)) {
					$this->_log('warning', 'Entra OAuth state validation failed.');
					return false;
				}

				// Verifying received tokens with Entra and finalizing authentication
				$params = [
					'grant_type' => 'authorization_code',
					'client_id' => $this->client_id,
					'redirect_uri' => $this->redirect_uri,
					'code' => $codeFromRequest,
					'client_secret' => $this->client_secret
				];

				$options = [
					'header'  => [
						'Content-Type' => 'application/x-www-form-urlencoded'
					]
				];
				$url = $this->auth_provider . $this->entra_tenant . "/oauth2/v2.0/token";

				$response = ($this->_createHttpSocket())->post($url, $params, $options);

				if (!$response->isOk()) {
					$this->_log("warning", "Error received during Bearer token fetch (context).");
					$this->_logHttpError("debug", $url, $response);
					return false;
				}

				$authdata = json_decode($response->body, true);
				if (isset($authdata["error"])) {
					$this->_log("warning", "Error received during Bearer token fetch (authdata).");
					$this->_log("debug", "Response: " . json_encode($authdata["error"]));
					return false;
				}

				$this->_log("info", "Fetching user data from Microsoft Graph.");

				$options = [
					'header'  => [
						'Accept' => 'application/json',
						'Authorization' => 'Bearer ' . $authdata["access_token"]
					]
				];
				$url = $this->auth_provider_user . "/v1.0/me";

				$response = ($this->_createHttpSocket())->get($url, null, $options);

				if (!$response->isOk()) {
					$this->_log("warning", "Error received during user data fetch.");
					$this->_logHttpError("debug", $url, $response);
					return false;
				}

				$userdata = json_decode($response->body, true);  //This should now contain your logged on user information
				if (isset($userdata["error"])) {
					$this->_log("warning", "User data fetch contained an error.");
					$this->_log("debug", "Response: " . json_encode($userdata["error"]));
					return false;
				}

				if (!isset($userdata[$this->auth_property_name])) {
					$this->_log('warning', "Authentication property `" . $this->auth_property_name . "` not found in Entra response.");
					return false;
				}

				$mispUsername = $userdata[$this->auth_property_name];
				if (filter_var($mispUsername, FILTER_VALIDATE_EMAIL) === false) {
					$this->_log('warning', "Entra authentication property value `{$mispUsername}` is not a valid email address.");
					return false;
				}

				$groups = $this->_fetchEntraGroups($authdata);
				if ($groups === false) {
					return false;
				}

				$roleId = $this->_resolveRoleId($groups, $mispUsername);
				if (!$roleId) {
					return false;
				}

				$orgId = $this->_resolveOrganisationId($userdata, $mispUsername);
				if (!$orgId) {
					$this->_log('warning', "No organisation available for Entra user `{$mispUsername}`.");
					return false;
				}

				$this->_log("info", "Attempt Entra authentication for `{$mispUsername}`");
				$user = $this->_findUser($mispUsername);
				$userModel = ClassRegistry::init($this->settings['userModel']);

				if ($user) {
					if ($this->update_user_role && (int)$user['role_id'] !== (int)$roleId) {
						$userModel->updateField($user, 'role_id', $roleId);
						$this->_log('info', "User role changed from {$user['role_id']} to {$roleId} for `{$mispUsername}`.");
						$user['role_id'] = (int)$roleId;
					}
					if ($this->update_user_org && (int)$user['org_id'] !== (int)$orgId) {
						$userModel->updateField($user, 'org_id', $orgId);
						$this->_log('info', "User organisation changed from {$user['org_id']} to {$orgId} for `{$mispUsername}`.");
						$user['org_id'] = (int)$orgId;
					}
					$userModel->extralog($user, 'login');
					$this->_log("info", "Entra authentication successful for `{$mispUsername}`");
					session_regenerate_id(true);
					return $user;
				}

				$user = $this->_createUser($mispUsername, (int)$roleId, (int)$orgId);
				if ($user) {
					$userModel->extralog($user, 'login');
					$this->_log("info", "Entra authentication successful for `{$mispUsername}`");
					session_regenerate_id(true);
				}
				return $user;
			}
		}

		// fall back
		return false;
	}

	/**
	 * Create a local MISP user for a validated Entra principal.
	 *
	 * @param string $mispUsername
	 * @param int $roleId
	 * @param int $orgId
	 * @return array|false
	 */
	private function _createUser($mispUsername, $roleId, $orgId)
	{
		/** @var User $userModel */
		$userModel = ClassRegistry::init($this->settings['userModel']);
		$userData = [
			'User' => [
				'email' => $mispUsername,
				'org_id' => $orgId,
				'newsread' => time(),
				'role_id' => $roleId,
				'change_pw' => 0,
				'date_created' => time(),
			]
		];

		$userModel->create();
		if (!$userModel->save($userData)) {
			$this->_log('warning', "Failed to create local Entra user `{$mispUsername}`.");
			$this->_log('debug', 'User model validation errors: ' . json_encode($userModel->validationErrors));
			return false;
		}

		$this->_log('info', "Local Entra user `{$mispUsername}` created in database.");

		return $this->_findUser($mispUsername);
	}

	/**
	 * Resolve organisation from user claims or fallback config.
	 *
	 * @param array $userdata
	 * @param string $mispUsername
	 * @return int|false
	 */
	private function _resolveOrganisationId(array $userdata, $mispUsername)
	{
		$orgName = isset($userdata[$this->organisation_property]) ? $userdata[$this->organisation_property] : null;
		$orgUuid = isset($userdata[$this->organisation_uuid_property]) ? $userdata[$this->organisation_uuid_property] : null;

		$orgId = $this->_checkOrganization($orgName, $orgUuid, $mispUsername);
		if ($orgId) {
			return $orgId;
		}

		return $this->_defaultOrganisationId();
	}

	/**
	 * Fetch organisation ID from database by provided name and UUID.
	 * If organisation is not found and name is provided, it is created.
	 *
	 * @param string|null $orgName
	 * @param string|null $orgUuid
	 * @param string $mispUsername
	 * @return int|false
	 */
	private function _checkOrganization($orgName, $orgUuid, $mispUsername)
	{
		$orgModel = ClassRegistry::init('Organisation');
		if (empty($orgName)) {
			$this->_log('info', "Organisation claim `" . $this->organisation_property . "` not provided for `{$mispUsername}`.");
			return false;
		}

		if (!empty($orgUuid) && !Validation::uuid($orgUuid)) {
			$this->_log('warning', "Organisation UUID `{$orgUuid}` is invalid for `{$mispUsername}`.");
			return false;
		}

		$orgNameIsUuid = Validation::uuid($orgName);
		$conditions = ['OR' => []];

		if (!empty($orgUuid)) {
			$conditions['OR']['Organisation.uuid'] = strtolower($orgUuid);
		}
		if ($orgNameIsUuid) {
			$conditions['OR']['Organisation.uuid'] = strtolower($orgName);
		} else {
			$conditions['OR']['Organisation.name'] = $orgName;
		}

		$orgAux = $orgModel->find('first', [
			'fields' => ['Organisation.id', 'Organisation.name'],
			'conditions' => $conditions,
		]);

		if (!empty($orgAux['Organisation']['id'])) {
			return (int) $orgAux['Organisation']['id'];
		}

		if (!empty($orgUuid) && !$orgNameIsUuid) {
			$existingByName = $orgModel->find('first', [
				'fields' => ['Organisation.id', 'Organisation.uuid'],
				'conditions' => ['name' => $orgName],
			]);
			if (!empty($existingByName['Organisation']['id'])) {
				$this->_log(
					'info',
					"Organisation `{$orgName}` already exists with ID {$existingByName['Organisation']['id']}; reusing existing organisation instead of creating a duplicate."
				);
				return (int)$existingByName['Organisation']['id'];
			}
		}

		if ($orgNameIsUuid) {
			$this->_log('warning', "Could not find organisation with UUID `{$orgName}` for `{$mispUsername}`.");
			return false;
		}

		$orgId = $orgModel->createOrgFromName($orgName, 0, true, $orgUuid);
		$this->_log('info', "User organisation `{$orgName}` created with ID {$orgId}.");

		return (int)$orgId;
	}

	/**
	 * Resolve configured default organisation.
	 *
	 * @return int|false
	 */
	private function _defaultOrganisationId()
	{
		$defaultOrg = $this->default_org;
		if (empty($defaultOrg)) {
			return false;
		}

		$orgModel = ClassRegistry::init('Organisation');
		if (is_numeric($defaultOrg)) {
			$conditions = ['id' => $defaultOrg];
		} elseif (Validation::uuid($defaultOrg)) {
			$conditions = ['uuid' => strtolower($defaultOrg)];
		} else {
			$conditions = ['name' => $defaultOrg];
		}

		$orgAux = $orgModel->find('first', [
			'fields' => ['Organisation.id'],
			'conditions' => $conditions,
		]);

		if (empty($orgAux['Organisation']['id'])) {
			$this->_log('warning', "Could not resolve default organisation `{$defaultOrg}`.");
			return false;
		}

		return (int)$orgAux['Organisation']['id'];
	}

	/**
	 * Resolve role for Entra user from group mapping.
	 *
	 * @param array $groups
	 * @param string $mispUsername
	 * @return int|false
	 */
	private function _resolveRoleId(array $groups, $mispUsername)
	{
		$roleMapper = $this->role_mapper;
		if (empty($roleMapper)) {
			$roleMapper = $this->_legacyRoleMapper();
		}

		if (!is_array($roleMapper)) {
			$this->_log('warning', 'EntraID role mapper config is invalid, expected array.');
			return false;
		}

		foreach ($roleMapper as $entraGroup => $mispRole) {
			if (!in_array($entraGroup, $groups, true)) {
				continue;
			}
			$roleId = $this->_resolveRoleIdByValue($mispRole);
			if ($roleId) {
				return $roleId;
			}
			$this->_log('warning', "Mapped role `{$mispRole}` for group `{$entraGroup}` was not found.");
		}

		if (!$this->check_entra_groups) {
			$defaultRoleId = $this->_getConfiguredDefaultRoleId();
			if ($defaultRoleId) {
				return $defaultRoleId;
			}
		}

		$this->_log('warning', "No group mapping match found for Entra user `{$mispUsername}`.");
		return false;
	}

	/**
	 * Legacy fallback mapping using existing EntraAuth group config keys.
	 *
	 * @return array
	 */
	private function _legacyRoleMapper()
	{
		$mapper = [];
		if (!empty($this->misp_siteadmin)) {
			$mapper[$this->misp_siteadmin] = '__siteadmin';
		}
		if (!empty($this->misp_orgadmin)) {
			$mapper[$this->misp_orgadmin] = '__orgadmin';
		}
		if (!empty($this->misp_user)) {
			$mapper[$this->misp_user] = '__default';
		}
		return $mapper;
	}

	/**
	 * Resolve role ID from configured mapper value.
	 *
	 * @param mixed $mispRole
	 * @return int|false
	 */
	private function _resolveRoleIdByValue($mispRole)
	{
		if ($mispRole === '__siteadmin') {
			return $this->_getRoleIdByConditions(['Role.perm_site_admin' => 1]);
		}
		if ($mispRole === '__orgadmin') {
			return $this->_getRoleIdByConditions([
				'Role.perm_site_admin' => 0,
				'Role.perm_admin' => 1
			]);
		}
		if ($mispRole === '__default') {
			return $this->_getConfiguredDefaultRoleId();
		}
		if (is_numeric($mispRole)) {
			return (int)$mispRole;
		}

		$roleModel = ClassRegistry::init('Role');
		$roleNameToId = $roleModel->find('list', [
			'fields' => ['Role.name', 'Role.id'],
		]);
		$roleNameToId = array_change_key_case($roleNameToId);

		$normalizedRoleName = mb_strtolower((string)$mispRole);
		if (!isset($roleNameToId[$normalizedRoleName])) {
			return false;
		}

		return (int)$roleNameToId[$normalizedRoleName];
	}

	/**
	 * Fetch Entra group names for the current user.
	 *
	 * @param array $authdata
	 * @return array|false
	 */
	private function _fetchEntraGroups(array $authdata)
	{
		if (!$this->check_entra_groups && empty($this->role_mapper)) {
			return [];
		}

		$this->_log("info", "Fetching user group data from Microsoft Graph.");
		$options = [
			'header'  => [
				'Accept' => 'application/json',
				'Authorization' => 'Bearer ' . $authdata["access_token"]
			]
		];

		$groups = [];
		$hasNextPage = true;
		$pageCount = 0;
		$maxPageCount = 50;
		$url = $this->auth_provider_user . "/v1.0/me/memberOf";

		while ($hasNextPage) {
			$pageCount++;
			if ($pageCount > $maxPageCount) {
				$this->_log('warning', 'Entra group pagination exceeded the safety limit.');
				return false;
			}

			$response = ($this->_createHttpSocket())->get($url, [], $options);
			if (!$response->isOk()) {
				$this->_log("warning", "Error received during user group data fetch.");
				$this->_logHttpError("debug", $url, $response);
				return false;
			}

			$groupdata = json_decode($response->body, true);
			if (isset($groupdata["error"])) {
				$this->_log("warning", "Group data fetch contained an error.");
				$this->_log("debug", "Response: " . json_encode($groupdata["error"]));
				return false;
			}

			foreach ($groupdata['value'] as $group) {
				if (!empty($group['displayName'])) {
					$groups[] = $group['displayName'];
				}
			}

			$hasNextPage = array_key_exists('@odata.nextLink', $groupdata);
			if ($hasNextPage) {
				$url = $groupdata['@odata.nextLink'];
			}
		}

		$groups = array_values(array_unique($groups));
		if ($this->check_entra_groups && empty($groups)) {
			$this->_log('warning', 'The user is not a member of any Entra groups.');
		}

		return $groups;
	}

	/**
	 * Fetch the configured default role for new users.
	 *
	 * @return int|false
	 */
	private function _getConfiguredDefaultRoleId()
	{
		$roleModel = ClassRegistry::init('Role');
		$defaultRole = $roleModel->find('first', [
			'recursive' => -1,
			'conditions' => ['Role.default_role' => 1],
			'fields' => ['Role.id'],
			'order' => 'Role.id ASC'
		]);

		if (!empty($defaultRole['Role']['id'])) {
			return (int) $defaultRole['Role']['id'];
		}

		$roleId = Configure::read('MISP.userDefaults.role_id');
		return $roleId ? (int) $roleId : false;
	}

	/**
	 * Find a role matching the provided conditions.
	 *
	 * @param array $conditions
	 * @return int|false
	 */
	private function _getRoleIdByConditions(array $conditions)
	{
		$roleModel = ClassRegistry::init('Role');
		$role = $roleModel->find('first', [
			'recursive' => -1,
			'conditions' => $conditions,
			'fields' => ['Role.id'],
			'order' => 'Role.id ASC'
		]);

		if (empty($role['Role']['id'])) {
			return false;
		}

		return (int) $role['Role']['id'];
	}

	/**
	 * Create HttpSocket with proxy settings
	 * 
	 * @return HttpSocket
	 */
	private function _createHttpSocket()
	{
		$httpSocket = new HttpSocket();
		$proxy = Configure::read('Proxy');
		if (isset($proxy['host']) && !empty($proxy['host'])) {
			$httpSocket->configProxy($proxy['host'], $proxy['port'], $proxy['method'], $proxy['user'], $proxy['password']);
		}

		return $httpSocket;
	}
}
