<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Tests\OAuth2ServerTest.
 */


namespace Drupal\oauth2_server\Tests;

use Drupal\Core\Url;
use Drupal\Core\Site\Settings;
use Drupal\simpletest\WebTestBase;
use Drupal\oauth2_server\Utility;


/**
 * Tests oauth2 server.
 *
 * @group oauth2_server
 */
class OAuth2ServerTest extends WebTestBase {
  /**
   * The profile to install as a basis for testing.
   *
   * @var string
   */
  protected $profile = 'testing';

  /**
   * Modules to install.
   *
   * @var array
   */
  public static $modules = array('oauth2_server', 'oauth2_server_test');

  /**
   * The client key of the test client.
   *
   * @var string
   */
  protected $clientId = 'test_client';

  /**
   * The client secret of the test client.
   *
   * @var string
   */
  protected $clientSecret = 'test_secret';

  /**
   * The redirect uri used on multiple locations.
   */
  protected $redirectUri;

  /**
   * The public key X.509 certificate used for all tests with encryption.
   *
   * @var string
   */
  protected $publicKey = '-----BEGIN CERTIFICATE-----
MIIDMDCCApmgAwIBAgIBADANBgkqhkiG9w0BAQQFADB0MS0wKwYDVQQDEyRodHRw
czovL21hcmtldHBsYWNlLmludGVybmFsLmMtZy5pby8xCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTQwMTIxMTYyMzAyWhcNMTQwMTIzMTYyMzAyWjB0MS0wKwYDVQQD
EyRodHRwczovL21hcmtldHBsYWNlLmludGVybmFsLmMtZy5pby8xCzAJBgNVBAYT
AkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANVMpjmyWlaD
6N1x1O4cf5PB6fXjq4dx1zKh/znG/zMJhkaT0TNJDD+3zfpJYFFxZGrbde+dYinL
jDK+ROvq7+h+93r0eWrld+R/kNWgILJtWwXQACPDd0pVtdOiSSd90QSEfRZyyYCl
n8RvVIPdPbGiPtDQGDwV5Dc5WcupdJNBAgMBAAGjgdEwgc4wHQYDVR0OBBYEFO4C
ZtCI7/REm9UO+PFpbAAsHHOUMIGeBgNVHSMEgZYwgZOAFO4CZtCI7/REm9UO+PFp
bAAsHHOUoXikdjB0MS0wKwYDVQQDEyRodHRwczovL21hcmtldHBsYWNlLmludGVy
bmFsLmMtZy5pby8xCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEw
HwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQQFAAOBgQCSCeFzNdUeFh0yNVatOdQpm2du1v7A4NXpdWL5
tXJQpv3Vgohc9f2GrVr1np270aJ3rzmSrWugZRHx0A3zhuYTNsapacvIOqmffPHd
0IZVnRgXnHPqwnWqMWuNtb8DglEEjKarjnOos/RbGvbirWsAJObxnt9kfI5wUOoA
0mYehA==
-----END CERTIFICATE-----';

  /**
   * The private key used for all tests with encryption.
   *
   * @var string
   */
  protected $privateKey = '-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDVTKY5slpWg+jdcdTuHH+Twen146uHcdcyof85xv8zCYZGk9Ez
SQw/t836SWBRcWRq23XvnWIpy4wyvkTr6u/ofvd69Hlq5Xfkf5DVoCCybVsF0AAj
w3dKVbXTokknfdEEhH0WcsmApZ/Eb1SD3T2xoj7Q0Bg8FeQ3OVnLqXSTQQIDAQAB
AoGAa/aEHKgd+bSC5bN8Z5mdKZj5ZzB53fDNUB+XJBOJkLe9c3PWa/MJdCcA5zLE
wfR3M28p3sL2sNkKeZS9JfyguU0QQzMhrnJZMSwPzrcUEVcRI/3vCvgnWr/4UFBW
JQpdWGvmk9MNg83y/ddnIBHEQRI9POz/dt/4L58Vq5YUy8ECQQDuWHV2nMmvuAiW
/s+D+S8arhfUyupNEVhNvpqMxK/25s4rUHGadIWm2TPStWEyxQGE4Om4bcw8KOLw
iAeKQ/qFAkEA5RlDJHz0CEgW4+bM+rOIi+tLB2C+TLzKH0eDGpeImAdsk4Z53Lxm
22iZm3DtkEqrrl+bYiaQVFovtbd5wmS4jQJBALFlcXfo1kxNA0evO7CUZLTM4rvk
k2LtB/ZFaS5grj9sJgMjCorVMyyt+N5ZVZC+BJVr+Ujln98e51nzRPlqAykCQQC/
9rT94/2O2ujjOcdT4g9uPk/19KhAIIi0QPWn2IVJ7h6aVrnRrcP54OGlD7DfkNHe
IJpQWcPiClejygMqUb8ZAkEA6SFArj46gwFaERr+D8wMizfZdxhzEuMMG3angAuV
1VPFI7qyv4rtDVATTk8RXeXUcP7l3JaQbqh+Jf0d1eSUpg==
-----END RSA PRIVATE KEY-----';

  /**
   * {@inheritdoc}
   */
  protected function setUp() {
    parent::setUp();

    $this->redirectUri = $this->buildUrl('authorized', ['absolute' => TRUE]);

    // Set the keys so that the module can see them.
    $keys = array(
      'public_key' => $this->publicKey,
      'private_key' => $this->privateKey,
    );
    \Drupal::state()->set('oauth2_server.keys', $keys);
    \Drupal::state()->set('oauth2_server.last_generated', REQUEST_TIME);

    /** @var \Drupal\oauth2_server\ServerInterface $server */
    $server = $this->container->get('entity.manager')->getStorage('oauth2_server')->create([
      'server_id' => 'test_server',
      'name' => 'Test Server',
      'settings' => [
        'default_scope' => 'test_server_basic',
        'enforce_state' => TRUE,
        'allow_implicit' => TRUE,
        'use_openid_connect' => TRUE,
        'use_crypto_tokens' => FALSE,
        'store_encrypted_token_string' => FALSE,
        'grant_types' => array(
          'authorization_code' => 'authorization_code',
          'client_credentials' => 'client_credentials',
          'urn:ietf:params:oauth:grant-type:jwt-bearer' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'refresh_token' => 'refresh_token',
          'password' => 'password',
        ),
        'always_issue_new_refresh_token' => TRUE,
        'advanced_settings' => [
          'require_exact_redirect_uri' => TRUE,
          'access_lifetime' => 3600,
          'id_lifetime' => 3600,
          'refresh_token_lifetime' => 1209600,
        ]
      ]
    ]);
    $server->save();

    /** @var \Drupal\oauth2_server\ClientInterface $client */
    $client = $this->container->get('entity.manager')->getStorage('oauth2_server_client')->create([
      'client_id' => $this->clientId,
      'server_id' => $server->id(),
      'name' => 'Test client',
      'unhashed_client_secret' => $this->clientSecret,
      'public_key' => $this->publicKey,
      'redirect_uri' => 'https://google.com' . "\n" . $this->redirectUri,
      'automatic_authorization' => TRUE,
    ]);
    $client->save();

    $scopes = array(
      'basic' => 'Basic',
      'admin' => 'Admin',
      'forbidden' => 'Forbidden',
      'phone' => 'phone',
      // Already generated by the server for the OpenID Connect:
      // 'openid', 'email', 'offline_access', 'profile' => 'Profile'.
    );
    foreach ($scopes as $scope_name => $scope_label) {
      $scope = $this->container->get('entity.manager')->getStorage('oauth2_server_scope')->create([
        'scope_id' => $scope_name,
        'server_id' => $server->id(),
        'description' => $scope_label,
      ]);
      $scope->save();
    }
  }

  /**
   * Performs an authorization request and returns it.
   *
   * Used to test authorization, the implicit flow, and the authorization_code
   * grant type.
   *
   * @return
   *   The return value of $this->drupalGet().
   */
  protected function authorizationCodeRequest($response_type, $scope = NULL) {
    $query = array(
      'response_type' => $response_type,
      'client_id' => $this->clientId,
      'state' => \Drupal\Component\Utility\Crypt::hmacBase64($this->clientId, Settings::getHashSalt()),
      'redirect_uri' => $this->redirectUri,
      // OpenID Connect requests require a nonce. Others ignore it.
      'nonce' => 'test',
    );
    if ($scope) {
      $query['scope'] = $scope;
    }

    $authorize_url = $this->buildUrl(new Url('oauth2_server.authorize'), ['query' => $query]);
    return $this->httpGetRequest($authorize_url);
  }

  /**
   * Tests the authorization part of the flow.
   */
  public function testAuthorization() {
    // Create a user, log him in, and retry the request.
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);
    $result = $this->authorizationCodeRequest('code');

    // Test the redirect_uri and authorization code.
    $redirect_url_parts = explode('?', $result->headers['location']);
    $authorize_redirect = FALSE;
    if ($result->code == 302 && $redirect_url_parts[0] == $this->redirectUri) {
      $authorize_redirect = TRUE;
    }
    $this->assertTrue($authorize_redirect, 'User was properly redirected to the "redirect_uri".');

    $redirect_url_params = $this->getRedirectParams($result);
    $this->assertTrue($redirect_url_params['code'], 'The server returned an authorization code');
    $valid_token = $redirect_url_params['state'] == \Drupal\Component\Utility\Crypt::hmacBase64($this->clientId, Settings::getHashSalt());
    $this->assertTrue($valid_token, 'The server returned a valid state');
  }

  /**
   * Tests the implicit flow.
   */
  public function testImplicitFlow() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);
    $result = $this->authorizationCodeRequest('token');

    $this->assertEqual($result->code, 302, 'The implicit flow request completed successfully');
    $response = $this->getRedirectParams($result, '#');
    $this->assertTokenResponse($response, FALSE);

    // We have received an access token. Verify it.
    // See http://drupal.org/node/1958718.
    if (!empty($response['access_token'])) {
      $verification_url = $this->buildUrl(new Url('oauth2_server.tokens', ['oauth2_server_token' => $response['access_token']]));
      $result = $this->httpGetRequest($verification_url);
      $verification_response = json_decode($result->data);
      $this->assertEqual($result->code, 200, 'The provided access token was successfully verified.');
      $this->verbose($verification_response->scope);
      $this->verbose(urldecode($response['scope']));
      $this->assertEqual($verification_response->scope, urldecode($response['scope']), 'The provided scope matches the scope of the verified access token.');
    }
  }

  /**
   * Tests the "Authorization code" grant type.
   */
  public function testAuthorizationCodeGrantType() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);
    // Perform authorization and get the code.
    $result = $this->authorizationCodeRequest('code');
    $redirect_url_params = $this->getRedirectParams($result);
    $authorization_code = $redirect_url_params['code'];

    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'authorization_code',
      'code' => $authorization_code,
      'redirect_uri' => $this->redirectUri,
    );
    $result = $this->httpPostRequest($token_url, $data);

    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    $this->assertTokenResponse($response);
  }

  /**
   * Tests the "Client credentials" grant type.
   */
  public function testClientCredentialsGrantType() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);
    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'client_credentials',
    );
    $result = $this->httpPostRequest($token_url, $data);

    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    $this->assertTokenResponse($response, FALSE);
  }

  /**
   * Tests the "JWT bearer" grant type.
   */
  public function testJwtBearerGrantType() {
    $jwt_util = new \OAuth2\Encryption\Jwt();
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);

    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $jwt_data = array(
      'iss' => $this->clientId,
      'exp' => time() + 1000,
      'iat' => time(),
      'sub' => $user->id(),
      'aud' => $token_url,
      'jti' => '123456',
    );
    $data = array(
      'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'assertion' => $jwt_util->encode($jwt_data, $this->privateKey, 'RS256'),
    );
    $result = $this->httpPostRequest($token_url, $data, FALSE);

    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    $this->assertTokenResponse($response, FALSE);
  }

  /**
   * Tests the "User credentials" grant type.
   */
  public function testPasswordGrantType() {
    $result = $this->passwordGrantRequest();
    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    $this->assertTokenResponse($response);
  }

  /**
   * Tests the "Refresh token" grant type.
   */
  public function testRefreshTokenGrantType() {
    // Do a password grant first, in order to get the refresh token.
    $result = $this->passwordGrantRequest();
    $response = json_decode($result->data);
    $refresh_token = $response->refresh_token;

    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'refresh_token',
      'refresh_token' => $refresh_token,
    );
    $result = $this->httpPostRequest($token_url, $data);

    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    // The response will include a new refresh_token because
    // always_issue_new_refresh_token is TRUE.
    $this->assertTokenResponse($response);
  }

  /**
   * Tests scopes.
   */
  public function testScopes() {
    // The default scope returned by oauth2_server_default_scope().
    $result = $this->passwordGrantRequest();
    $response = json_decode($result->data);
    $this->assertEqual($response->scope, 'admin basic', 'The correct default scope was returned.');

    // A non-existent scope.
    $result = $this->passwordGrantRequest('invalid_scope');
    $response = json_decode($result->data);
    $error = isset($response->error) && $response->error == 'invalid_scope';
    $this->assertTrue($error, 'Invalid scope correctly detected.');

    // A scope forbidden by oauth2_server_scope_access.
    // @see oauth2_server_test_entity_query_alter()
    $result = $this->passwordGrantRequest('forbidden');
    $response = json_decode($result->data);
    $error = isset($response->error) && $response->error == 'invalid_scope';
    $this->assertTrue($error, 'Inaccessible scope correctly detected.');

    // A specific requested scope.
    $result = $this->passwordGrantRequest('admin');
    $response = json_decode($result->data);
    $this->assertEqual($response->scope, 'admin', 'The correct scope was returned.');
  }


  /**
   * Tests the OpenID Connect authorization code flow.
   */
  function testOpenIdConnectAuthorizationCodeFlow() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);

    // Perform authorization without the offline_access scope.
    // No refresh_token should be returned from the /token endpoint.
    $result = $this->authorizationCodeRequest('code', 'openid');
    $redirect_url_params = $this->getRedirectParams($result);
    $authorization_code = $redirect_url_params['code'];

    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'authorization_code',
      'code' => $authorization_code,
      'redirect_uri' => $this->redirectUri,
    );
    $result = $this->httpPostRequest($token_url, $data);

    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    $this->assertTokenResponse($response, FALSE);
    if (!empty($response->id_token)) {
      $this->assertIdToken($response->id_token);
    }
    else {
      $this->assertTrue(FALSE, 'The token request returned an id_token.');
    }

    // Perform authorization witho the offline_access scope.
    // A refresh_token should be returned from the /token endpoint.
    $result = $this->authorizationCodeRequest('code', 'openid offline_access');
    $redirect_url_params = $this->getRedirectParams($result);
    $authorization_code = $redirect_url_params['code'];

    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'authorization_code',
      'code' => $authorization_code,
      'redirect_uri' => $this->redirectUri,
    );
    $result = $this->httpPostRequest($token_url, $data);

    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    $this->assertTokenResponse($response);
    if (!empty($response->id_token)) {
      $this->assertIdToken($response->id_token);
    }
    else {
      $this->assertTrue(FALSE, 'The token request returned an id_token.');
    }
  }

  /**
   * Tests the OpenID Connect implicit flow.
   */
  function testOpenIdConnectImplicitFlow() {
    $account = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($account);
    $result = $this->authorizationCodeRequest('id_token', 'openid email');
    $this->assertEqual($result->code, 302, 'The "id_token" implicit flow request completed successfully');
    $response = $this->getRedirectParams($result, '#');
    if (!empty($response['id_token'])) {
      $this->assertIdToken($response['id_token'], FALSE, $account);
    }
    else {
      $this->assertTrue(FALSE, 'The token request returned an id_token.');
    }

    $result = $this->authorizationCodeRequest('token id_token', 'openid email profile phone');
    $this->assertEqual($result->code, 302, 'The "token id_token" implicit flow request completed successfully');
    $response = $this->getRedirectParams($result, '#');
    $this->assertTokenResponse($response, FALSE);
    if (!empty($response['id_token'])) {
      $this->assertIdToken($response['id_token'], TRUE);
    }
    else {
      $this->assertTrue(FALSE, 'The token request returned an id_token.');
    }

    $account->timezone = 'Europe/London';
    $account->save();

    // Request OpenID Connect user information (claims).
    $query = array(
      'access_token' => $response['access_token'],
    );
    $info_url = $this->buildUrl(new Url('oauth2_server.userinfo'), ['query' => $query]);
    $result = $this->httpGetRequest($info_url);
    $response = json_decode($result->data);

    $expected_claims = array(
      'sub' => $account->id(),
      'email' => $account->mail->value,
      'email_verified' => TRUE,
      'phone_number' => '123456',
      'phone_number_verified' => FALSE,
      'preferred_username' => $account->name->value,
      'name' => $account->label(),
      'zoneinfo' => $account->timezone->value,
    );

    foreach ($expected_claims as $claim => $expected_value) {
      $this->assertEqual($response->$claim, $expected_value, 'The UserInfo endpoint returned a valid "' . $claim . '" claim');
    }
  }

  /**
   * Tests that the OpenID Connect 'sub' property affects user info 'sub' claim.
   */
  public function testOpenIdConnectNonDefaultSub() {
    $this->config('oauth2_server.oauth')->set('user_sub_property', 'name')->save();
    $result = $this->passwordGrantRequest('openid');
    $response = json_decode($result->data);
    $access_token = $response->access_token;

    $query = array(
      'access_token' => $access_token,
    );
    $info_url = $this->buildUrl(new Url('oauth2_server.userinfo'), ['query' => $query]);
    $result = $this->httpGetRequest($info_url);
    $response = json_decode($result->data, TRUE);
    $this->assertEqual($this->loggedInUser->name->value, $response['sub'], 'The UserInfo "sub" is now the user\'s name.');
  }

  /**
   * Tests that the OpenID Connect 'sub' property affects ID token 'sub' claim.
   */
  public function testOpenIdConnectNonDefaultSubInIdToken() {
    $this->config('oauth2_server.oauth')->set('user_sub_property', 'name')->save();

    // This is the authorization code grant type flow.
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);
    $result = $this->authorizationCodeRequest('code', 'openid offline_access');
    $redirect_url_params = $this->getRedirectParams($result);
    $authorization_code = $redirect_url_params['code'];

    // Get tokens using the authorization code.
    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'authorization_code',
      'code' => $authorization_code,
      'redirect_uri' => $this->redirectUri,
    );
    $result = $this->httpPostRequest($token_url, $data);
    $response = json_decode($result->data);

    $parts = explode('.', $response->id_token);
    $claims = json_decode(Utility::base64urlDecode($parts[1]), TRUE);
    $this->assertEqual($this->loggedInUser->name->value, $claims['sub'], 'The ID token "sub" is now the user\'s name.');
  }

  /**
   * Tests crypto tokens.
   */
  public function testCryptoTokens() {
    // Enable crypto tokens.
    $server = $this->container->get('entity.manager')->getStorage('oauth2_server')->load('test_server');
    $server->settings['use_crypto_tokens'] = TRUE;
    $server->save();

    $result = $this->passwordGrantRequest();
    $this->assertEqual($result->code, 200, 'The token request completed successfully');
    $response = json_decode($result->data);
    // The refresh token is contained inside the crypto token.
    $this->assertTokenResponse($response, FALSE);

    $verified = FALSE;
    if (substr_count($response->access_token, '.') == 2) {
      // Verify the JTW Access token following the instructions from
      // http://bshaffer.github.io/oauth2-server-php-docs/overview/jwt-access-tokens
      list($header, $payload, $signature) = explode('.', $response->access_token);
      // The signature is "url safe base64 encoded".
      $signature = base64_decode(strtr($signature, '-_,', '+/'));
      $payload_to_verify = utf8_decode($header . '.' . $payload);
      $verified = openssl_verify($payload_to_verify, $signature, $this->publicKey, 'sha256');
    }
    $this->assertTrue($verified, 'The JWT Access Token is valid.');
  }

  /**
   * Tests resource requests.
   */
  public function testResourceRequests() {
    $result = $this->passwordGrantRequest('admin');
    $response = json_decode($result->data);
    $access_token = $response->access_token;

    // Check resource access with no access token.
    $resource_url = $this->buildUrl(new Url('oauth2_server_test.resource', ['oauth2_server_scope' => 'admin']));
    $result = $this->httpGetRequest($resource_url);
    $this->assertEqual($result->code, 401, 'Missing access token correctly detected.');

    // Check resource access with an insufficient scope.
    $query = array(
      'access_token' => $access_token,
    );
    $resource_url = $this->buildUrl(new Url('oauth2_server_test.resource', ['oauth2_server_scope' => 'forbidden'], ['query' => $query]));
    $result = $this->httpGetRequest($resource_url);
    $response = json_decode($result->data);
    $error = isset($response->error) && $response->error == 'insufficient_scope';
    $this->assertTrue($error, 'Insufficient scope correctly detected.');

    // Check resource access with the access token in the url.
    $query = array(
      'access_token' => $access_token,
    );
    $resource_url = $this->buildUrl(new Url('oauth2_server_test.resource', ['oauth2_server_scope' => 'admin'], ['query' => $query]));
    $result = $this->httpGetRequest($resource_url);
    $this->assertEqual($result->code, 200, 'Access token in the URL correctly detected.');

    // Check resource access with the access token in the header.
    $resource_url = $this->buildUrl(new Url('oauth2_server_test.resource', ['oauth2_server_scope' => 'admin']));
    $headers = [
      'Authorization: Bearer ' . $access_token,
    ];
    $result = $this->httpGetRequest($resource_url, [], $headers);
    $this->assertEqual($result->code, 200, 'Access token in the header correctly detected.');
  }

  /**
   * Test that access is denied when using a token for a blocked user.
   */
  public function testBlockedUserTokenFails() {
    // Get a normal access token for a normal user.
    $result = $this->passwordGrantRequest('admin');
    $response = json_decode($result->data);
    $access_token = $response->access_token;

    // Check resource access while the user is active.
    $resource_url = $this->buildUrl(new Url('oauth2_server_test.resource', ['oauth2_server_scope' => 'admin']));
    $headers = [
      'Authorization: Bearer ' . $access_token,
    ];
    $result = $this->httpGetRequest($resource_url, [], $headers);
    $this->assertEqual($result->code, 200, 'An active user is correctly authenticated.');

    // Block the user.
    $this->loggedInUser->status = 0;
    $this->loggedInUser->save();

    // Check resource access while the user is blocked.
    $result = $this->httpGetRequest($resource_url, [], $headers);
    $this->assertEqual($result->code, 403, 'A blocked user is denied access with 403 Forbidden.');
  }

  /**
   * Assert that the given token response has the expected values.
   *
   * @param $response
   *   The response (either an object decoded from a json string or the
   *   query string taken from the url in case of the implicit flow).
   * @param $has_refresh_token
   *   A boolean indicating whether this response should have a refresh token.
   */
  protected function assertTokenResponse($response, $has_refresh_token = TRUE) {
    // Make sure we have an array.
    $response = (array) $response;

    $this->assertTrue(array_key_exists('access_token', $response), 'The "access token" value is present in the return values');
    $this->assertTrue(array_key_exists('expires_in', $response), 'The "expires_in" value is present in the return values');
    $this->assertTrue(array_key_exists('token_type', $response), 'The "token_type" value is present in the return values');
    $this->assertTrue(array_key_exists('scope', $response), 'The "scope" value is present in the return values');
    if ($has_refresh_token) {
      $this->assertTrue(array_key_exists('refresh_token', $response), 'The "refresh_token" value is present in the return values');
    }
  }

  /**
   * Assert that the given id_token response has the expected values.
   *
   * @param $id_token
   *   The id_token.
   * @param $has_at_hash
   *   Whether the token is supposed to contain the at_hash claim.
   * @param $account
   *   The account of the authenticated user, if the id_token is supposed
   *   to contain user claims.
   */
  protected function assertIdToken($id_token, $has_at_hash = FALSE, $account = NULL) {
    $parts = explode('.', $id_token);
    list($headerb64, $claims64, $signatureb64) = $parts;
    $claims = json_decode(Utility::base64urlDecode($claims64), TRUE);
    $signature = Utility::base64urlDecode($signatureb64);

    $payload = utf8_decode($headerb64 . '.' . $claims64);
    $verified = openssl_verify($payload, $signature, $this->publicKey, 'sha256');
    $this->assertTrue($verified, 'The id_token has a valid signature.');

    $this->assertTrue(array_key_exists('iss', $claims), 'The id_token contains an "iss" claim.');
    $this->assertTrue(array_key_exists('sub', $claims), 'The id_token contains a "sub" claim.');
    $this->assertTrue(array_key_exists('aud', $claims), 'The id_token contains an "aud" claim.');
    $this->assertTrue(array_key_exists('iat', $claims), 'The id_token contains an "iat" claim.');
    $this->assertTrue(array_key_exists('exp', $claims), 'The id_token contains an "exp" claim.');
    $this->assertTrue(array_key_exists('auth_time', $claims), 'The id_token contains an "auth_time" claim.');
    $this->assertTrue(array_key_exists('nonce', $claims), 'The id_token contains a "nonce" claim');
    if ($has_at_hash) {
      $this->assertTrue(array_key_exists('at_hash', $claims), 'The id_token contains an "at_hash" claim.');
    }
    if ($account) {
      $this->assertTrue(array_key_exists('email', $claims), 'The id_token contains an "email" claim.');
      $this->assertTrue(array_key_exists('email_verified', $claims), 'The id_token contains an "email_verified" claim.');
    }

    $this->assertEqual($claims['aud'], $this->clientId, 'The id_token "aud" claim contains the expected client_id.');
    $this->assertEqual($claims['nonce'], 'test', 'The id_token "nonce" claim contains the expected nonce.');
    if ($account) {
      $this->assertEqual($claims['email'], $account->mail->getValue()[0]['value']);
    }
  }

  /**
   * Performs a password grant request and returns it.
   *
   * Used to test the grant itself, as well as a helper for other tests
   * (since it's a fast way of getting an access token).
   *
   * @param $scope
   *   An optional scope to request.
   *
   * @return
   *   The return value of $this->httpRequest().
   */
  protected function passwordGrantRequest($scope = NULL) {
    $user = $this->drupalCreateUser(array('use oauth2 server'));
    $this->drupalLogin($user);

    $token_url = $this->buildUrl(new Url('oauth2_server.token'));
    $data = array(
      'grant_type' => 'password',
      'username' => $user->name->getValue()[0]['value'],
      'password' => $user->pass_raw,
    );
    if ($scope) {
      $data['scope'] = $scope;
    }

    return $this->httpPostRequest($token_url, $data);
  }

  public function getRedirectParams($result, $explode = '?') {
    $redirect_url_parts = explode($explode, $result->headers['location']);

    $response = [];
    parse_str($redirect_url_parts[1], $response);
    return $response;
  }


  public function httpGetRequest($url, $options = [], $headers = []) {
    // Need the redirect location for OAuth2 testing.
    $this->maximumRedirects = 0;

    $result = new \stdClass();
    $result->data = $this->drupalGet($url, $options, $headers);
    $result->code = curl_getinfo($this->curlHandle, CURLINFO_HTTP_CODE);
    $result->headers = $this->drupalGetHeaders();
    $result->request_headers = $headers;
    $this->verbose(print_r($result, TRUE));

    // Set back to original.
    $this->maximumRedirects = 5;

    return $result;
  }

  public function httpPostRequest($url, $data = [], $authorization = TRUE) {
    $curl_options = [
      CURLOPT_URL => $url,
      CURLOPT_POST => TRUE,
      CURLOPT_POSTFIELDS => $this->serializePostValues($data),
      CURLOPT_HTTPHEADER => [
        'Accept: application/json',
        'Content-Type: application/x-www-form-urlencoded',
      ],
    ];
    if ($authorization) {
      $curl_options[CURLOPT_HTTPHEADER][] = 'Authorization: Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret);
    }

    // Need the redirect location for OAuth2 testing.
    $this->maximumRedirects = 0;

    $result = new \stdClass();
    $result->data = $this->curlExec($curl_options);
    $result->code = curl_getinfo($this->curlHandle, CURLINFO_HTTP_CODE);
    $result->headers = $this->drupalGetHeaders();
    $result->request_url = $url;
    $result->request_options = $curl_options;
    $result->request_data = $data;
    $this->verbose(print_r($result, TRUE));

    // Set back to original.
    $this->maximumRedirects = 5;

    return $result;
  }
}
