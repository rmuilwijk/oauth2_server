<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Utility.
 */

namespace Drupal\oauth2_server;

use Drupal\Core\Url;
use OAuth2\HttpFoundationBridge\Response as BridgeResponse;
use OAuth2\HttpFoundationBridge\Request as BridgeRequest;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use Drupal\oauth2_server\ServerInterface;
use Drupal\oauth2_server\OAuth2StorageInterface;
use Drupal\oauth2_server\ScopeUtility;

/**
 * Contains utility methods for the OAuth2 Server.
 *
 * @todo Maybe move some of these methods to other classes (and/or split this
 *   class into several utility classes).
 */
class Utility {
  /**
   * Returns an array of supported grant types and related data.
   */
  public static function getGrantTypes() {
    return array(
      'authorization_code' => array(
        'name' => t('Authorization code'),
        'class' => '\OAuth2\OpenID\GrantType\AuthorizationCode',
      ),
      'client_credentials' => array(
        'name' => t('Client credentials'),
        'class' => '\OAuth2\GrantType\ClientCredentials',
      ),
      'urn:ietf:params:oauth:grant-type:jwt-bearer' => array(
        'name' => t('JWT bearer'),
        'class' => '\OAuth2\GrantType\JwtBearer',
      ),
      'refresh_token' => array(
        'name' => t('Refresh token'),
        'class' => '\OAuth2\GrantType\RefreshToken',
        'settings callback' => array(__NAMESPACE__ .'\Form\ServerForm', 'refreshTokenSettings'),
        'default settings' => array(
          'always_issue_new_refresh_token' => FALSE,
          'unset_refresh_token_after_use' => TRUE,
        ),
      ),
      'password' => array(
        'name' => t('User credentials'),
        'class' => '\OAuth2\GrantType\UserCredentials',
      ),
    );
  }

  /**
   * Decodes base64url encoded data.
   *
   * @param string $data
   *   A string containing the base64url encoded data.
   *
   * @return string|FALSE
   *   The decoded data, or FALSE on failure.
   */
  public static function base64urlDecode($data) {
    $data = str_replace(array('-', '_'), array('+', '/'), $data);
    return base64_decode($data);
  }

  /**
   * Encodes a string as base64url.
   *
   * @param string $data
   *   The string to encode.
   *
   * @return string
   *   The encoded data.
   */
  public static function base64urlEncode($data) {
    return str_replace(array('+', '/'), array('-', '_'), base64_encode($data));
  }

  /**
   * Returns the pair of private and public keys used to sign tokens.
   *
   * @return array
   *   An array with the following keys:
   *   - private_key: The private key.
   *   - public_key: The public key certificate (PEM encoded X.509).
   *
   * @see oauth2_server_generate_keys()
   */
  public static function getKeys() {
    $keys = \Drupal::state()->get('oauth2_server.keys', FALSE);
    if (!$keys) {
      $keys = static::generateKeys();
      \Drupal::state()->set('oauth2_server.keys', $keys);
    }

    return $keys;
  }

  /**
   * Generates a pair of private and public keys using OpenSSL.
   *
   * The public key is stored in a PEM encoded X.509 certificate, following
   * Google's example. The certificate can be passed to openssl_verify() directly.
   *
   * @return array
   *   An array with the following keys:
   *   - private_key: The generated private key.
   *   - public_key: The generated public key certificate (PEM encoded X.509).
   */
  public static function generateKeys() {
    $module_path = drupal_get_path('module', 'oauth2_server');
    $config = array(
      'config' => $module_path . '/oauth2_server.openssl.cnf',
    );

    // Generate a private key.
    $resource = openssl_pkey_new($config);
    openssl_pkey_export($resource, $private_key);

    // Generate a public key certificate valid for 2 days.
    $serial = \Drupal::state()->get('oauth2_server.next_certificate_id', 0);
    $uri = new Url('<front>' , [], ['absolute' => TRUE, 'https' => TRUE]);
    $dn = array(
      'CN' => $uri->toString(),
    );
    $csr = openssl_csr_new($dn, $resource, $config);
    $x509 = openssl_csr_sign($csr, NULL, $resource, 2, $config, $serial);
    openssl_x509_export($x509, $public_key_certificate);
    // Increment the id for next time. db_next_id() is not used since it can't
    // guarantee sequential numbers.
    \Drupal::state()->set('oauth2_server.next_certificate_id', ++$serial);

    return array(
      'private_key' => $private_key,
      'public_key' => $public_key_certificate,
    );
  }

  /**
   * Initializes and returns an OAuth2 server.
   *
   * @param \Drupal\oauth2_server\ServerInterface|NULL $server
   *   The server entity to use for supplying settings to the server, and
   *   initializing the scope. NULL only when we expect the validation to
   *   fail due to an incomplete or invalid request.
   *
   * @param \Drupal\oauth2_server\OAuth2StorageInterface $storage
   *   The storage service to use for retrieving data.
   *
   * @return \OAuth2\Server
   *   An instance of OAuth2\Server.
   */
  public static function startServer(ServerInterface $server = NULL, OAuth2StorageInterface $storage) {
    $grant_types = static::getGrantTypes();
    if ($server) {
      $uri = new Url('<front>' , [], ['absolute' => TRUE, 'https' => TRUE]);
      $settings = $server->settings + array(
          'issuer' => $uri->toString(),
        );

      // The setting 'use_crypto_tokens' was changed to 'use_jwt_access_tokens' in
      // v1.6 of the library. So this provides both.
      $settings['use_jwt_access_tokens'] = !empty($settings['use_crypto_tokens']) ?: FALSE;

      // Initialize the server and add the scope util.
      $oauth2_server = new \OAuth2\Server($storage, $settings);
      $scope_util = new \Drupal\oauth2_server\ScopeUtility($server);
      $oauth2_server->setScopeUtil($scope_util);
      // Determine the available grant types based on server settings.
      $enabled_grant_types = array_filter($settings['grant_types']);
    }
    else {
      $oauth2_server = new \OAuth2\Server($storage);
      // Enable all grant types. One of them will handle the validation failure.
      $enabled_grant_types = array_keys($grant_types);
      $settings = array();
    }

    // Initialize the enabled grant types.
    foreach ($enabled_grant_types as $grant_type_name) {
      if ($grant_type_name == 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
        $audience = new Url('oauth2_server.token', [], ['absolute' => TRUE]);
        $grant_type = new $grant_types[$grant_type_name]['class']($storage, $audience->toString());
      }
      else {
        $grant_type = new $grant_types[$grant_type_name]['class']($storage, $settings);
      }
      $oauth2_server->addGrantType($grant_type);
    }
    // Implicit flow requires its own instance of OAuth2_GrantType_AuthorizationCode.
    if (!empty($settings['allow_implicit'])) {
      $grant_type = new \OAuth2\OpenID\GrantType\AuthorizationCode($storage, $settings);
      $oauth2_server->addGrantType($grant_type, 'implicit');
    }

    return $oauth2_server;
  }

  /**
   * Get the client credentials from the authorization header or the request body.
   *
   * Used during token requests.
   *
   * @param \OAuth2\HttpFoundationBridge\Request $request
   *   An instance of \OAuth2\HttpFoundationBridge\Request.
   *
   * @return array|NULL
   *   An array with the following keys:
   *   - client_id: The client key.
   *   - client_secret: The client secret.
   *   or NULL if no client credentials were found.
   */
  public static function getClientCredentials(RequestInterface $request) {
    // Get the client credentials from the Authorization header.
    if (!is_null($request->headers('PHP_AUTH_USER'))) {
      return array(
        'client_id' => $request->headers('PHP_AUTH_USER'),
        'client_secret' => $request->headers('PHP_AUTH_PW', ''),
      );
    }

    // Get the client credentials from the request body (POST).
    // Per spec, this method is not recommended and should be limited to clients
    // unable to utilize HTTP authentication.
    if (!is_null($request->request('client_id'))) {
      return array(
        'client_id' => $request->request('client_id'),
        'client_secret' => $request->request('client_secret', ''),
      );
    }

    // This request contains a JWT, extract the client_id from there.
    if (!is_null($request->request('assertion'))) {
      $jwt_util = new \OAuth2\Encryption\Jwt();
      $jwt = $jwt_util->decode($request->request('assertion'), NULL, FALSE);
      if (!empty($jwt['iss'])) {
        return array(
          'client_id' => $jwt['iss'],
          // The JWT bearer grant type doesn't use the client_secret.
          'client_secret' => '',
        );
      }
    }

    return NULL;
  }

  /**
   * Returns whether the current site needs to have keys generated.
   *
   * @return bool
   *   TRUE if at least one server uses JWT Access Tokens or OpenID Connect,
   *   FALSE otherwise.
   */
  public static function siteNeedsKeys() {
    $servers = \Drupal::entityManager()->getStorage('oauth2_server')->loadMultiple();
    foreach ($servers as $server) {
      if (!empty($server->settings['use_crypto_tokens'])) {
        return TRUE;
      }
      if (!empty($server->settings['use_openid_connect'])) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Check access for the passed server and scope.
   *
   * @param string $server_name
   *   The name of the server for which access should be verified.
   * @param string $scope
   *   An optional string of space-separated scopes to check.
   *
   * @return \OAuth2\Response|array
   *   A valid access token if found, otherwise an \OAuth2\Response object
   *   containing an appropriate response message and status code.
   */
  public static function checkAccess($server_name, $scope = NULL) {
    $server = \Drupal::entityManager()->getStorage('oauth2_server')->load($server_name);
    $storage = \Drupal::service('oauth2_server.storage');
    $oauth2_server = Utility::startServer($server, $storage);
    $response = new BridgeResponse();

    $request = \Drupal::requestStack()->getCurrentRequest();
    $bridgeRequest = BridgeRequest::createFromRequest($request);

    $token = $oauth2_server->getAccessTokenData($bridgeRequest, $response);
    // If there's no token, that means validation failed. Stop here.
    if (!$token) {
      return $response;
    }

    // Make sure that the token we have matches our server.
    if ($token['server'] != $server->id()) {
      $response->setError(401, 'invalid_grant', 'The access token provided is invalid');
      $response->addHttpHeaders(array('WWW-Authenticate' => sprintf('%s, realm="%s", scope="%s"', 'bearer', 'Service', $scope)));
      return $response;
    }

    // Check scope, if provided
    // If token doesn't have a scope, it's null/empty, or it's insufficient, throw an error.
    $scope_util = new ScopeUtility($server);
    if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$scope_util->checkScope($scope, $token["scope"]))) {
      $response->setError(401, 'insufficient_scope', 'The request requires higher privileges than provided by the access token');
      $response->addHttpHeaders(array('WWW-Authenticate' => sprintf('%s, realm="%s", scope="%s"', 'bearer', 'Service', $scope)));
      return $response;
    }

    return $token;
  }
}
