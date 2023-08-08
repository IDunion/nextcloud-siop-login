<?php

namespace OCA\OIDCLogin\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\Files\IAppData;
use OCP\IL10N;
use OCP\IRequest;
use Psr\Log\LoggerInterface;
use OCP\IConfig;
use OCP\IUserSession;
use OCP\IUserManager;
use OCP\IURLGenerator;
use OCP\IGroupManager;
use OCP\ISession;
use OCP\AppFramework\Utility\ITimeFactory;
use OC\User\LoginException;
use OC\Authentication\Token\IProvider;
use OCP\AppFramework\Http\Template\PublicTemplateResponse;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\TextPlainResponse;
use OCA\OIDCLogin\Db\Token;
use OCA\OIDCLogin\Db\TokenMapper;
use OCA\OIDCLogin\Db\RequestObjectMapper;
use OCA\OIDCLogin\Helper\AuthenticationRequest;
use OCA\OIDCLogin\Credentials\Anoncreds\AnoncredVerifier;

require_once __DIR__ . '/../../3rdparty/autoload.php';

use chillerlan\QRCode\QRCode;
use Ramsey\Uuid\Uuid;

use JsonPath\JsonObject;
use OCA\OIDCLogin\Credentials\W3CVerifiableCredentials\VCVerifier;
use OCA\OIDCLogin\Helper\PresentationExchangeHelper;
use OCA\OIDCLogin\Helper\SdJwtPresentationExchangeHelper;
use OCA\OIDCLogin\Credentials\SdJwt\SdJwtVerifier;


class LoginController extends Controller
{
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;
    /** @var IUserManager */
    private $userManager;
    /** @var IUserSession */
    private $userSession;
    /** @var IGroupManager */
    private $groupManager;
    /** @var ISession */
    private $session;
    /** @var IL10N */
    private $l;
    /** @var \OCA\Files_External\Service\GlobalStoragesService */
    private $storagesService;
    /** @var IAppData */
    private $appData;
    /** @var LoggerInterface */
    private $logger;
    /** @var IProvider */
    private $tokenProvider;


    public function __construct(
        $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        IUserManager $userManager,
        IUserSession $userSession,
        IGroupManager $groupManager,
        ISession $session,
        IProvider $tokenProvider,
        IL10N $l,
        IAppData $appData,
        TokenMapper $tokenMapper,
        RequestObjectMapper $requestObjectMapper,
        ITimeFactory $timeFactory,
        LoggerInterface $logger,
        $storagesService
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userManager = $userManager;
        $this->userSession = $userSession;
        $this->groupManager = $groupManager;
        $this->session = $session;
        $this->tokenProvider = $tokenProvider;
        $this->l = $l;
        $this->appData = $appData;
        $this->tokenMapper = $tokenMapper;
        $this->requestObjectMapper = $requestObjectMapper;
        $this->timeFactory = $timeFactory;
        $this->logger = $logger;
        $this->storagesService = $storagesService;
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function oidc()
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }

        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return $this->redirectToMainPage();
        }
        
        // Generate nonce compatible with the IndySDK
        $nonce = strval(random_int(0, 9223372036854775807)) . strval(random_int(0, 9223372036854775807));
        $this->session['nonce'] = $nonce;

        // Generate UUID4 as presentation ID
        $presentationID = Uuid::uuid4()->toString();
        $this->session['presentationID'] = $presentationID;

        $ar = new AuthenticationRequest(
            $this->appName,
            $this->urlGenerator,
            $this->timeFactory,
            $this->config,
            $this->requestObjectMapper,
            $nonce,
            $presentationID,
            $this->logger
        );

        $arUrlPost = $ar->createCrossDevice();
        $this->logger->debug('Created cross-device authentication requests: '. $arUrlPost);

        $arUrlAsQrCode = (new QRCode())->render($arUrlPost);

        $arUrl = $ar->createOnDevice();
        $this->logger->debug('Created on-device authentication requests: '. $arUrl);
        
        $params = array(
            'qr' => $arUrlAsQrCode,
            'arPost' => $arUrlPost,
            'ar' => $arUrl,
            'pollingUri' => $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.polling'),
            'callbackUri' => $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback'),
            'backButton' => $this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm'),
        );

        return new PublicTemplateResponse($this->appName, 'AuthorizationRequest', $params);
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     */
    public function requestObject($id)
    {
        $requestUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.requestObject', array('id' => $id));
        
        try {
            $requestObject = $this->requestObjectMapper->find($requestUri)->getRequestObject();
            $this->logger->debug('Get request object. request_uri: ' . $requestUri .  ', request object: ' . $requestObject);
            return new TextPlainResponse($requestObject, Http::STATUS_OK);
        } catch (DoesNotExistException $e) {
            $this->logger->warning('Request object not found. request_uri: ' . $requestUri);
            return new TextPlainResponse('', Http::STATUS_NOT_FOUND);
        }
    }

    private function saveTokens(string $presentationSubmissionRaw, string $vpTokenRaw, bool $used, bool $viaPost)
    {
        // Extract presentation ID from presentation submission
        $presentationSubmission = new JsonObject($presentationSubmissionRaw, true);
        $presentationID = $presentationSubmission->get('$.definition_id');

        if (!empty($presentationID)) {
            $token = new Token();
            $token->setPresentationId($presentationID);
            $token->setPresentationSubmission($presentationSubmissionRaw);
            $token->setVpToken($vpTokenRaw);
            $token->setUsed($used);
            $token->setViaPost($viaPost);
            $token->setCreationTimestamp($this->timeFactory->getTime());
            $this->tokenMapper->insert($token);
            return $token;
        }
        return null;
    }

    private function getTokens($presentationID)
    {
        try {
            return $this->tokenMapper->find($presentationID);
        } catch (DoesNotExistException $e) {
            return null;
        }
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     */
    public function backend($presentation_submission, $vp_token)
    {
        $this->logger->debug('Received token via POST request. presentation_submission: ' . $presentation_submission . ' vp_token: ' . $vp_token);
        $this->saveTokens($presentation_submission, $vp_token, false, true);
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     */
    public function polling()
    {
        $presentationID = $this->session['presentationID'];
        if (!is_null($presentationID)) {
            $tokens = $this->getTokens($presentationID);
            // In case of on-device flow wait until the login process is finished
            // to redirect the original tab to the home folder.
            if (!is_null($tokens) && ($tokens->getViaPost() || $tokens->getUsed())) {
                $this->logger->debug('Found tokens - Via Post: ' . $tokens->getViaPost() . ' Used: ' . $tokens->getUsed());
                return new JSONResponse(array('finished' => true));
            }
        } else {
            $this->logger->error('Polling endpoint was called with a session that does not contain a presentationID');
        }
        return new JSONResponse(array('finished' => false));
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function callback($presentation_submission='', $vp_token='')
    {
        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return $this->redirectToMainPage();
        }

        $nonceFromSession = $this->session['nonce'];
        $presentationIdFromSession = $this->session['presentationID'];
             
        // check if we have tokens for this session in the database
        $tokens = $this->getTokens($presentationIdFromSession);
        if (!empty($tokens)) {
            // if the tokens where already used redirect to user to the main page
            if ($tokens->getUsed()) {
                $this->logger->debug('Tokens where already used for login. Redirecting to the main page. Presentation ID: ' . $presentationIdFromSession);
                return $this->redirectToMainPage();
            }

            $presentationSubmissionRaw = $tokens->getPresentationSubmission();
            $vpTokenRaw = $tokens->getVpToken();
            $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.backend');
        } elseif (strlen($presentation_submission) != 0 && strlen($vp_token) != 0) {
            // if no tokens are in the database look for the ones in the GET parameter
            $presentationSubmissionRaw = $presentation_submission;
            $vpTokenRaw = $vp_token;
            // save tokens in database
            $this->saveTokens($presentationSubmissionRaw, $vpTokenRaw, false, false);
            $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        } else {
            // if no tokens where found, cancel login with error page
            $this->logger->debug('No id_token or vp_token passed to callback method. Presentation ID: ' . $presentationIdFromSession);
            $this->logger->error('No id_token or vp_token passed to callback method');
            throw new LoginException("No presentation_definition or vp_token passed to callback method");
        }

        $this->logger->debug('Callback received presentation_submission: ' . $presentationSubmissionRaw . ' and vp_token: ' . $vpTokenRaw);
        
        // Check whether an Anoncred or an JSON-LD credential was sent
        $ps = new JsonObject($presentationSubmissionRaw, true);
        if ($ps->get('$.descriptor_map[0].id') == PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID) {
            /********************************************************************************
             * Process Hyperledger Indy Anoncred Credential
             ********************************************************************************/
            $schemaConfig = $this->config->getSystemValue('oidc_login_anoncred_config', array());
            $profile = AnoncredVerifier::verify(
                $vpTokenRaw,
                $ps,
                $schemaConfig,
                $nonceFromSession,
                $presentationIdFromSession,
                $this->logger
            );
        } else if ($ps->get('$.descriptor_map[0].id') == PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID) {
            /********************************************************************************
             * Process W3C Verifiable Credential in JSON-LD format with BBS+ signature
             ********************************************************************************/
            $jsonldConfig = $this->config->getSystemValue('oidc_login_jsonld_config', array());
            $profile = VCVerifier::verify(
                $vpTokenRaw,
                $ps,
                $presentationIdFromSession,
                $nonceFromSession,
                $jsonldConfig,
                $this->logger
            );
        } else if ($ps->get('$.descriptor_map[0].id') == SdJwtPresentationExchangeHelper::INPUT_DESCRIPTOR_ID) {
            /********************************************************************************
             * Process SD-JWT credential
             ********************************************************************************/
            $sdJwtConfig = $this->config->getSystemValue('oidc_login_sdjwt_config', array());
            $profile = SdJwtVerifier::verify(
                $vpTokenRaw,
                $ps,
                $presentationIdFromSession,
                $nonceFromSession,
                $redirectUri,
                $sdJwtConfig,
                $this->logger,
            );
        } else {
            $this->logger->debug('presentation_submission does not contain a valid Presentation Submission: '.$ps->getJson());
            $this->logger->error('presentation_submission does not contain a valid Presentation Submission');
            throw new LoginException('presentation_submission does not contain a valid Presentation Submission');
        }
        
        return $this->login($profile);
    }

    private function login($profile)
    {
        // Get attributes
        $confattr = $this->config->getSystemValue('oidc_login_attributes', array());
        $defattr = array(
            'id' => 'sub',
            'name' => 'name',
            'mail' => 'email',
            'quota' => 'ownCloudQuota',
            'home' => 'homeDirectory',
            'ldap_uid' => 'uid',
            'groups' => 'ownCloudGroups',
        );
        $attr = array_merge($defattr, $confattr);

        $joinAttr = $this->config->getSystemValue('oidc_login_join_attributes', array());
        foreach ($joinAttr as $key => $values) {
            $profile[$key] = '';
            foreach ($values as $v) {
                if (array_key_exists($v, $profile)) {
                    $profile[$key] = $profile[$key] . ' ' . $profile[$v];
                }
            }
            $profile[$key] = trim($profile[$key]);
        }

        // Flatten the profile array
        $profile = $this->flatten($profile);

        //var_dump($profile);
        //throw new LoginException('DEBUG');

        // Get UID
        $uid = $profile[$attr['id']];

        // Ensure the LDAP user exists if we are proxying for LDAP
        if ($this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            // Get LDAP uid
            $ldapUid = $profile[$attr['ldap_uid']];
            if (empty($ldapUid)) {
                throw new LoginException($this->l->t('No LDAP UID found in OpenID response'));
            }

            // Get the LDAP user backend
            $ldap = null;
            foreach ($this->userManager->getBackends() as $backend) {
                if ($backend->getBackendName() == $this->config->getSystemValue('oidc_login_ldap_backend', "LDAP")) {
                    $ldap = $backend;
                }
            }

            // Check if backend found
            if ($ldap == null) {
                throw new LoginException($this->l->t('No LDAP user backend found!'));
            }

            // Get LDAP Access object
            $access = $ldap->getLDAPAccess($ldapUid);

            // Get the DN
            $dns = $access->fetchUsersByLoginName($ldapUid);
            if (empty($dns)) {
                throw new LoginException($this->l->t('Error getting DN for LDAP user'));
            }
            $dn = $dns[0];

            // Store the user
            $ldapUser = $access->userManager->get($dn);
            if ($ldapUser == null) {
                throw new LoginException($this->l->t('Error getting user from LDAP'));
            }

            // Method no longer exists on NC 20+
            if (method_exists($ldapUser, 'update')) {
                $ldapUser->update();
            }

            // Update the email address (#84)
            if (method_exists($ldapUser, 'updateEmail')) {
                $ldapUser->updateEmail();
            }

            // Force a UID for existing users with a different
            // user ID in nextcloud than in LDAP
            $uid = $ldap->dn2UserName($dn) ?: $uid;
        }

        // Check UID
        if (empty($uid)) {
            throw new LoginException($this->l->t('Can not get identifier from provider'));
        }

        // Check max length of uid
        if (strlen($uid) > 64) {
            $uid = md5($uid);
        }

        // Get user with fallback
        $user = $this->userManager->get($uid);
        $userPassword = '';

        // Create user if not existing
        if (null === $user) {
            if ($this->config->getSystemValue('oidc_login_disable_registration', true)) {
                throw new LoginException($this->l->t('Auto creating new users is disabled'));
            }

            $userPassword = substr(base64_encode(random_bytes(64)), 0, 30);
            $user = $this->userManager->createUser($uid, $userPassword);
        }

        $this->logger->debug('Going to login user with username: ' . $uid . ', display name: ' . $user->getDisplayName() . ', user home: ' . $user->getHome());

        // Get base data directory
        $datadir = $this->config->getSystemValue('datadirectory');

        // Set home directory unless proxying for LDAP
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false) &&
             array_key_exists($attr['home'], $profile)) {

            // Get intended home directory
            $home = $profile[$attr['home']];

            if ($this->config->getSystemValue('oidc_login_use_external_storage', false)) {
                // Check if the files external app is enabled and injected
                if ($this->storagesService === null) {
                    throw new LoginException($this->l->t('files_external app must be enabled to use oidc_login_use_external_storage'));
                }

                // Check if the user already has matching storage on their root
                $storages = array_filter($this->storagesService->getStorages(), function ($storage) use ($uid) {
                    return in_array($uid, $storage->getApplicableUsers()) && // User must own the storage
                        $storage->getMountPoint() == "/" && // It must be mounted as root
                        $storage->getBackend()->getIdentifier() == 'local' && // It must be type local
                        count($storage->getApplicableUsers() == 1); // It can't be shared with other users
                });

                if (!empty($storages)) {
                    // User had storage on their / so make sure it's the correct folder
                    $storage = array_values($storages)[0];
                    $options = $storage->getBackendOptions();

                    if ($options['datadir'] != $home) {
                        $options['datadir'] = $home;
                        $storage->setBackendOptions($options);
                        $this->storagesService->updateStorage($storage);
                    }
                } else {
                    // User didnt have any matching storage on their root, so make one
                    $storage = $this->storagesService->createStorage('/', 'local', 'null::null', array(
                        'datadir' => $home
                    ), array(
                        'enable_sharing' => true
                    ));
                    $storage->setApplicableUsers([$uid]);
                    $this->storagesService->addStorage($storage);
                }
            } else {
                // Make home directory if does not exist
                mkdir($home, 0777, true);

                // Home directory (intended) of the user
                $nhome = "$datadir/$uid";

                // Check if correct link or home directory exists
                if (!file_exists($nhome) || is_link($nhome)) {
                    // Unlink if invalid link
                    if (is_link($nhome) && readlink($nhome) != $home) {
                        unlink($nhome);
                    }

                    // Create symlink to directory
                    if (!is_link($nhome) && !symlink($home, $nhome)) {
                        throw new LoginException("Failed to create symlink to home directory");
                    }
                }
            }
        }

        // Update user profile
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            if ($attr['name'] !== null) {
                $user->setDisplayName($profile[$attr['name']] ?: $profile[$attr['id']]);
            }

            if ($attr['mail'] !== null) {
                $user->setEMailAddress((string)$profile[$attr['mail']]);
            }

            // Set optional params
            if (array_key_exists($attr['quota'], $profile)) {
                $user->setQuota((string) $profile[$attr['quota']]);
            } else {
                if ($defaultQuota = $this->config->getSystemValue('oidc_login_default_quota')) {
                    $user->setQuota((string) $defaultQuota);
                };
            }

            // Groups to add user in
            $groupNames = [];

            // Add administrator group from attribute
            $manageAdmin = array_key_exists('is_admin', $attr) && $attr['is_admin'];
            if ($manageAdmin) {
                $adminAttr = $attr['is_admin'];
                if (array_key_exists($adminAttr, $profile) && $profile[$adminAttr]) {
                    array_push($groupNames, 'admin');
                }
            }

            // Add default group if present
            if ($defaultGroup = $this->config->getSystemValue('oidc_login_default_group')) {
                array_push($groupNames, $defaultGroup);
            }

            // Add user's groups from profile
            $hasProfileGroups = array_key_exists($attr['groups'], $profile);
            if ($hasProfileGroups) {
                // Get group names
                $profileGroups = $profile[$attr['groups']];

                // Explode by space if string
                if (is_string($profileGroups)) {
                    $profileGroups = array_filter(explode(' ', $profileGroups));
                }

                // Make sure group names is an array
                if (!is_array($profileGroups)) {
                    throw new LoginException($attr['groups'] . ' must be an array');
                }

                // Add to all groups
                $groupNames = array_merge($groupNames, $profileGroups);
            }

            // Remove duplicate groups
            $groupNames = array_unique($groupNames);

            // Remove user from groups not present
            $currentUserGroups = $this->groupManager->getUserGroups($user);
            foreach ($currentUserGroups as $currentUserGroup) {
                if (($key = array_search($currentUserGroup->getDisplayName(), $groupNames)) !== false) {
                    // User is already in group - don't process further
                    unset($groupNames[$key]);
                } else {
                    // User is not supposed to be in this group
                    // Remove the user ONLY if we're using profile groups
                    // or the group is the `admin` group and we manage admin role
                    if ($hasProfileGroups || ($manageAdmin && $currentUserGroup->getDisplayName() === 'admin')) {
                        $currentUserGroup->removeUser($user);
                    }
                }
            }

            // Add user to group
            foreach ($groupNames as $group) {
                // Get existing group
                $systemgroup = $this->groupManager->get($group);

                // Create group if does not exist
                if (!$systemgroup && $this->config->getSystemValue('oidc_create_groups', false)) {
                    $systemgroup = $this->groupManager->createGroup($group);
                }

                // Add user to group
                if ($systemgroup) {
                    $systemgroup->addUser($user);
                }
            }
        }

        // Complete login
        $this->userSession->getSession()->regenerateId();
        $this->userSession->setTokenProvider($this->tokenProvider);
        $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
        $token = $this->tokenProvider->getToken($this->userSession->getSession()->getId());

        $success = $this->userSession->completeLogin($user, [
            'loginName' => $user->getUID(),
            'password' => $userPassword,
            'token' => empty($userPassword) ? $token : null,
        ], false);

        $this->logger->debug('User: ' . $uid . ', login status: ' . $success . ', token: ' . $token->getToken());
        
        //Workaround to create user files folder. Remove it later.
        \OC::$server->query(\OCP\Files\IRootFolder::class)->getUserFolder($user->getUID());

        // Prevent being asked to change password
        $this->session->set('last-password-confirm', \OC::$server->query(ITimeFactory::class)->getTime());

        $this->logger->debug('Login successful');
        $this->markTokensAsUsed();

        return $this->redirectToMainPage();
    }

    private function redirectToMainPage()
    {
        // Go to redirection URI
        if ($redirectUrl = $this->session->get('login_redirect_url')) {
            $this->logger->debug("Redirecting user to login_redirect_url. Redirect URL: " . $redirectUrl);
            return new RedirectResponse($redirectUrl);
        }

        // Fallback redirection URI
        $redir = '/';
        if ($login_redir = $this->session->get('oidc_redir')) {
            $redir = $login_redir;
        }
        $redirectUrl = $this->urlGenerator->getAbsoluteURL($redir);
        $this->logger->debug("Redirecting user to main page. Redirect URL: " . $redirectUrl);
        return new RedirectResponse($redirectUrl);
    }

    private function markTokensAsUsed() {
        $presentationIdFromSession = $this->session['presentationID'];
        $tokens = $this->getTokens($presentationIdFromSession);
        $tokens->setUsed(true);
        $this->tokenMapper->update($tokens);
        $this->logger->debug('Tokens marked as used. PresentationID: ' . $presentationIdFromSession);
    }

    private function flatten($array, $prefix = '')
    {
        $result = array();
        foreach ($array as $key => $value) {
            $result[$prefix . $key] = $value;
            if (is_array($value)) {
                $result = $result + $this->flatten($value, $prefix . $key . '_');
            }
            if (is_int($key) && is_string($value)) {
                $result[$prefix . $value] = $value;
            }
        }
        return $result;
    }
}
