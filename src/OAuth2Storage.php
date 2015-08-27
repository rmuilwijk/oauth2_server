<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\OAuth2Storage.
 */

namespace Drupal\oauth2_server;

use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Password\PasswordInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\user\UserInterface;
use Drupal\oauth2_server\Utility;

/**
 * Provides Drupal OAuth2 storage for the library.
 */
class OAuth2Storage implements OAuth2StorageInterface {
  /**
   * The entity manager.
   *
   * @var \Drupal\Core\Entity\EntityManagerInterface
   */
  protected $entityManager;

  /**
   * The password hasher.
   *
   * @var \Drupal\Core\Password\PasswordInterface
   */
  protected $passwordHasher;

  /**
   * The module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * Constructs a new OAuth2Storage.
   *
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager.
   *
   * @param \Drupal\Core\Password\PasswordInterface $password_hasher
   *   The password hasher.
   */
  public function __construct(EntityManagerInterface $entity_manager, PasswordInterface $password_hasher, ModuleHandlerInterface $module_handler) {
    $this->entityManager = $entity_manager;
    $this->passwordHasher = $password_hasher;
    $this->moduleHandler = $module_handler;
  }

  /**
   * Retrieve the account from the storage.
   *
   * @param string $username
   *   The username or emailaddress of the account.
   *
   * @return bool|\Drupal\user\UserInterface
   *   The account loaded from the storage.
   */
  public function getStorageAccount($username) {
    $users = $this->entityManager->getStorage('user')->loadByProperties(['name' => $username]);
    if ($users) {
      return reset($users);
    }
    else {
      // An email address might have been supplied instead of the username.
      $users = $this->entityManager->getStorage('user')->loadByProperties(['mail' => $username]);
      if ($users) {
        return reset($users);
      }
    }

    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function getStorageClient($client_id) {
    $clients = $this->entityManager->getStorage('oauth2_server_client')->loadByProperties(['client_id' => $client_id]);
    if ($clients) {
      return reset($clients);
    }
    return FALSE;
  }


  /**
   * Get the token from the entity backend.
   *
   * @param string $token
   *   The token to find.
   *
   * @return \Drupal\oauth2_server\TokenInterface|bool
   *   Returns the token or FALSE.
   */
  public function getStorageToken($token) {
    $tokens = $this->entityManager->getStorage('oauth2_server_token')->loadByProperties(['token' => $token]);
    if ($tokens) {
      return reset($tokens);
    }
    return FALSE;
  }

  /**
   * Get the authorization code from the entity backend.
   *
   * @param string $code
   *   The code.
   *
   * @return \Drupal\oauth2_server\AuthorizationCodeInterface|bool
   *   Returns the code or FALSE.
   */
  public function getStorageAuthorizationCode($code) {
    $codes = $this->entityManager->getStorage('oauth2_server_authorization_code')->loadByProperties(['code' => $code]);
    if ($codes) {
      return reset($codes);
    }
    return FALSE;
  }

  /* ClientCredentialsInterface */
  public function checkClientCredentials($client_id, $client_secret = null) {
    $client = $this->getClientDetails($client_id);
    if (!$client) {
      return FALSE;
    }

    // The client may omit the client secret or provide NULL, and expect that to
    // be treated the same as an empty string.
    // See https://tools.ietf.org/html/rfc6749#section-2.3.1
    if ($client['client_secret'] === '' && ($client_secret === '' || $client_secret === NULL)) {
      return TRUE;
    }

    return $this->passwordHasher->check($client_secret, $client['client_secret']);
  }

  public function isPublicClient($client_id) {
    $client = $this->getClientDetails($client_id);
    return $client && empty($client['client_secret']);
  }

  public function getClientDetails($client_id) {
    $client = $this->getStorageClient($client_id);
    if ($client) {
      // Return a client array in the format expected by the library.
      $client = array(
        'client_id' => $client->client_id,
        'client_secret' => $client->client_secret,
        'public_key' => $client->public_key,
        // The library expects multiple redirect uris to be separated by
        // a space, but the module separates them by a newline, matching
        // Drupal behavior in other areas.
        'redirect_uri' => str_replace(array("\r\n", "\r", "\n"), ' ', $client->redirect_uri),
      );
    }

    return $client;
  }

  public function getClientScope($client_id) {
    // The module doesn't currently support per-client scopes.
    return NULL;
  }

  public function checkRestrictedGrantType($client_id, $grant_type) {
    $client = $this->getStorageClient($client_id);
    $server = $client->getServer();
    if (!empty($client->settings['override_grant_types'])) {
      $grant_types = array_filter($client->settings['grant_types']);
      $allow_implicit = $client->settings['allow_implicit'];
    }
    else {
      // Fallback to the global server settings.
      $grant_types = array_filter($server->settings['grant_types']);
      $allow_implicit = $server->settings['allow_implicit'];
    }

    // Implicit flow is enabled by a different setting, so it needs to be
    // added to the check separately.
    if ($allow_implicit) {
      $grant_types['implicit'] = 'implicit';
    }

    return in_array($grant_type, $grant_types);
  }

  /* AccessTokenInterface */
  public function getAccessToken($access_token) {
    $token = $this->getStorageToken($access_token);
    if (!$token) {
      return FALSE;
    }

    $user = $token->getUser();
    if ($user && $user->isBlocked()) {
      // If the user is blocked, deny access.
      return FALSE;
    }

    $scopes = array();
    $scope_entities = $token->scopes->referencedEntities();
    foreach ($scope_entities as $scope) {
      $scopes[] = $scope->scope_id;
    }
    sort($scopes);

    // Return a token array in the format expected by the library.
    $token_array = array(
      'server' => $token->getClient()->getServer()->id(),
      'client_id' => $token->getClient()->client_id,
      'user_id' => $user->id(),
      'user_uuid' => $user->uuid(),
      'access_token' => $token->token->value,
      'expires' => (int) $token->expires->value,
      'scope' => implode(' ', $scopes),
    );

    // Track last access on the token.
    $this->logAccessTime($token);

    return $token_array;
  }

  /**
   * Track the time the token was accessed.
   *
   * @param \Drupal\oauth2_server\TokenInterface $token
   */
  protected function logAccessTime(\Drupal\oauth2_server\TokenInterface $token) {
    if (empty($token->last_access->value) || $token->last_access->value != REQUEST_TIME) {
      $token->last_access = REQUEST_TIME;
      $token->save();
    }
  }

  public function setAccessToken($access_token, $client_id, $uid, $expires, $scope = null) {
    $client = $this->getStorageClient($client_id);
    if (!$client) {
      throw new \InvalidArgumentException("The supplied client couldn't be loaded.");
    }

    // If no token was found, start with a new entity.
    $token = $this->getStorageToken($access_token);
    if (!$token) {
      // The username is not required, the "Client credentials" grant type
      // doesn't provide it, for instance.
      if (!$uid || !$this->entityManager->getStorage('user')->load($uid)) {
        $uid = 0;
      }

      $token = $this->entityManager->getStorage('oauth2_server_token')->create(['type' => 'access']);
      $token->client_id = $client->id();
      $token->uid = $uid;
      $token->token = $access_token;
    }

    $token->expires = $expires;
    $this->setScopeData($token, $client->getServer(), $scope);

    $status = $token->save();
    return $status;
  }

  /* AuthorizationCodeInterface */
  public function getAuthorizationCode($code) {
    $code = $this->getStorageAuthorizationCode($code);
    if (!$code) {
      return FALSE;
    }

    $scopes = array();
    $scope_entities = $code->scopes->referencedEntities();
    foreach ($scope_entities as $scope) {
      $scopes[] = $scope->scope_id;
    }
    sort($scopes);

    // Return a code array in the format expected by the library.
    $code_array = array(
      'server' => $code->getClient()->getServer()->id(),
      'client_id' => $code->getClient()->client_id,
      'user_id' => $code->getUser()->id(),
      'user_uuid' => $code->getUser()->uuid(),
      'authorization_code' => $code->code->value,
      'redirect_uri' => $code->redirect_uri->value,
      'expires' => (int) $code->expires->value,
      'scope' => implode(' ', $scopes),
      'id_token' => $code->id_token->value,
    );

    // Examine the id_token and alter the OpenID Connect 'sub' property if
    // necessary. The 'sub' property is usually the user's UID, but this is
    // configurable for backwards compatibility reasons. See:
    // https://www.drupal.org/node/2274357#comment-9779467
    $sub_property = \Drupal::config('oauth2_server.oauth')->get('user_sub_property');
    if (!empty($code_array['id_token']) && $sub_property != 'uid') {
      $account = $code->getUser();
      $desired_sub = $account->{$sub_property}->value;
      $parts = explode('.', $code_array['id_token']);
      $claims = json_decode(Utility::base64urlDecode($parts[1]), TRUE);
      if (isset($claims['sub']) && $desired_sub != $claims['sub']) {
        $claims['sub'] = $desired_sub;
        $parts[1] = Utility::base64urlEncode(json_encode($claims));
        $code_array['id_token'] = implode('.', $parts);
      }
    }

    return $code_array;
  }

  public function setAuthorizationCode($code, $client_id, $uid, $redirect_uri, $expires, $scope = null, $id_token = null) {
    $client = $this->getStorageClient($client_id);
    if (!$client) {
      throw new \InvalidArgumentException("The supplied client couldn't be loaded.");
    }

    // If no code was found, start with a new entity.
    $authorization_code = $this->getStorageAuthorizationCode($code);
    if (!$authorization_code) {
      $user = $this->entityManager->getStorage('user')->load($uid);
      if (!$user) {
        throw new \InvalidArgumentException("The supplied user couldn't be loaded.");
      }

      $authorization_code = $this->entityManager->getStorage('oauth2_server_authorization_code')->create([]);
      $authorization_code->client_id = $client->id();
      $authorization_code->uid = $user->id();
      $authorization_code->code = $code;
      $authorization_code->id_token = $id_token;
    }

    $authorization_code->redirect_uri = $redirect_uri;
    $authorization_code->expires = $expires;
    $this->setScopeData($authorization_code, $client->getServer(), $scope);

    $status = $authorization_code->save();
    return $status;
  }

  public function expireAuthorizationCode($code) {
    $code = $this->getStorageAuthorizationCode($code);
    if ($code) {
      $code->delete();
    }
  }

  /* JwtBearerInterface */
  public function getClientKey($client_id, $subject) {
    // While the API supports a key per user (subject), the module only supports
    // one key per client, since it's the simpler and more frequent use case.
    $client = $this->getClientDetails($client_id);
    return $client ? $client['public_key'] : FALSE;
  }

  public function getJti($client_id, $subject, $audience, $expires, $jti) {
    $client = $this->getStorageClient($client_id);
    if (!$client) {
      // The client_id should be validated prior to this method being called,
      // but the library doesn't do that currently.
      return;
    }

    $found = $this->entityManager->getStorage('oauth2_server_jti')->loadByProperties([
      'client_id' => $client->id(),
      'subject' => $subject,
      'jti' => $jti,
      'expires' => $expires,
    ]);

    if ($found) {
      // JTI found, return the data back in the expected format.
      return array(
        'issuer' => $client_id,
        'subject' => $subject,
        'jti' => $jti,
        'expires' => $expires,
      );
    }
  }

  public function setJti($client_id, $subject, $audience, $expires, $jti) {
    $client = $this->getStorageClient($client_id);
    if (!$client) {
      // The client_id should be validated prior to this method being called,
      // but the library doesn't do that currently.
      return;
    }

    $entity = $this->entityManager->getStorage('oauth2_server_jti')->create([
      'client_id' => $client->id(),
      'subject' => $subject,
      'jti' => $jti,
      'expires' => $expires,
    ]);
    $entity->save();
  }

  /* UserCredentialsInterface */
  public function checkUserCredentials($username, $password) {
    $account = $this->getStorageAccount($username);

    if ($account && $account->isActive()) {
      return $this->passwordHasher->check($password, $account->getPassword());
    }

    return FALSE;
  }

  public function getUserDetails($username) {
    $account = $this->getStorageAccount($username);

    if ($account) {
      return array('user_id' => $account->id());
    }

    return FALSE;
  }

  /* UserClaimsInterface */
  public function getUserClaims($uid, $scope) {
    /** @var \Drupal\user\UserInterface $account */
    $account = $this->entityManager->getStorage('user')->load($uid);
    if (!$account) {
      throw new \InvalidArgumentException("The supplied user couldn't be loaded.");
    }
    $requested_scopes = explode(' ', trim($scope));

    // The OpenID Connect 'sub' (Subject Identifier) property is usually the
    // user's UID, but this is configurable for backwards compatibility reasons.
    // See: https://www.drupal.org/node/2274357#comment-9779467
    $sub_property = \Drupal::config('oauth2_server.oauth')->get('user_sub_property');

    // Prepare the default claims.
    $claims = array(
      'sub' => $account->{$sub_property}->value,
    );

    if (in_array('email', $requested_scopes)) {
      $claims['email'] = $account->getEmail();
      $claims['email_verified'] = \Drupal::config('user.settings')->get('verify_mail');
    }

    if (in_array('profile', $requested_scopes)) {
      if (!empty($account->label())) {
        $claims['name'] = $account->label();
        $claims['preferred_username'] = $account->label();
      }
      if (!empty($account->timezone)) {
        $claims['zoneinfo'] = $account->getTimeZone();
      }
      $anonymous_user = new AnonymousUserSession();
      if ($anonymous_user->hasPermission('access user profiles')) {
        $claims['profile'] = $account->url('canonical', ['absolute' => TRUE]);
      }
      if ($picture = $this->getUserPicture($account)) {
        $claims['picture'] = $picture;
      }
    }

    // Allow modules to supply additional claims.
    $claims += $this->moduleHandler->invokeAll('oauth2_server_user_claims', [
      'account' => $account,
      'requested_scopes' => $requested_scopes
    ]);

    // Finally, allow modules to alter claims.
    $context = [
      'claims' => &$claims,
      'account' => $account,
      'requested_scopes' => $requested_scopes,
    ];
    $this->moduleHandler->alter('oauth2_server_user_claims', $context);

    return $claims;
  }

  /* RefreshTokenInterface */
  public function getRefreshToken($refresh_token) {
    $token = $this->getStorageToken($refresh_token);
    if (!$token) {
      return FALSE;
    }

    $user = $token->getUser();
    if ($user && $user->isBlocked()) {
      // If the user is blocked, deny access.
      return FALSE;
    }

    $scopes = array();
    $scope_entities = $token->scopes->referencedEntities();
    foreach ($scope_entities as $scope) {
      $scopes[] = $scope->scope_id;
    }
    sort($scopes);

    $token_array = array(
      'server' => $token->getClient()->getServer()->id(),
      'client_id' => $token->getClient()->client_id,
      'user_id' => $token->getUser()->id(),
      'user_uuid' => $token->getUser()->uuid(),
      'refresh_token' => $token->token->value,
      'expires' => (int) $token->expires->value,
      'scope' => implode(' ', $scopes),
    );

    return $token_array;
  }

  public function setRefreshToken($refresh_token, $client_id, $uid, $expires, $scope = null) {
    $client = $this->getStorageClient($client_id);
    if (!$client) {
      throw new \InvalidArgumentException("The supplied client couldn't be loaded.");
    }

    // If no token was found, start with a new entity.
    $token = $this->getStorageToken($refresh_token);
    if (!$token) {
      $user = $this->entityManager->getStorage('user')->load($uid);
      if (!$user) {
        throw new \InvalidArgumentException("The supplied user couldn't be loaded.");
      }

      $token = $this->entityManager->getStorage('oauth2_server_token')->create(['type' => 'refresh']);
      $token->client_id = $client->id();
      $token->uid = $uid;
      $token->token = $refresh_token;
    }

    $token->expires = $expires;
    $this->setScopeData($token, $client->getServer(), $scope);
    $status = $token->save();

    return $status;
  }

  public function unsetRefreshToken($refresh_token) {
    $token = $this->getStorageToken($refresh_token);
    $token->delete();
  }

  /**
   * Sets the "scopes" entityreference field on the passed entity.
   *
   * @param $entity
   *   The entity containing the "scopes" entityreference field.
   * @param $server
   *   The machine name of the server.
   * @param $scope
   *   Scopes in a space-separated string.
   */
  private function setScopeData($entity, $server, $scope) {
    $entity->scopes = array();
    if ($scope) {
      $scopes = preg_split('/\s+/', $scope);
      $loaded_scopes = $this->entityManager->getStorage('oauth2_server_scope')->loadByProperties(['server_id' => $server->id(), 'scope_id' => $scopes]);
      ksort($loaded_scopes);
      foreach ($loaded_scopes as $loaded_scope) {
        $entity->scopes[] = $loaded_scope->id();
      }
    }
  }

  /* PublicKeyInterface */
  public function getPublicKey($client_id = null) {
    // The library allows for per-client keys. The module uses global keys
    // that are regenerated every day, following Google's example.
    $keys = Utility::getKeys();
    return $keys['public_key'];
  }

  public function getPrivateKey($client_id = null) {
    // The library allows for per-client keys. The module uses global keys
    // that are regenerated every day, following Google's example.
    $keys = Utility::getKeys();
    return $keys['private_key'];
  }

  public function getEncryptionAlgorithm($client_id = null) {
    return 'RS256';
  }

  /**
   * Get the user's picture to return as an OpenID Connect claim.
   *
   * @param \Drupal\user\UserInterface $account
   *   The user account object.
   *
   * @return string|NULL
   *   An absolute URL to the user picture, or NULL if none is found.
   */
  protected function getUserPicture(UserInterface $account) {
    if (!user_picture_enabled()) {
      return NULL;
    }

    if ($account->user_picture) {
      /** @var \Drupal\file\FileInterface $file */
      $file = $this->entityManager->getStorage('file')->load($account->user_picture->target_id);
      return $file->url('canonical', ['absolute' => TRUE]);
    }
    return FALSE;
  }
}
