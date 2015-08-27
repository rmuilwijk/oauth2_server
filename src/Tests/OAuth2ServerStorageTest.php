<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Tests\OAuth2ServerStorageTest.
 */


namespace Drupal\oauth2_server\Tests;

use Drupal\simpletest\WebTestBase;

/**
 * Tests oauth2 server storage.
 *
 * @group oauth2_server
 */
class OAuth2ServerStorageTest extends WebTestBase {
  /**
   * Modules to install.
   *
   * @var array
   */
  public static $modules = array('oauth2_server');

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
   * The storage instance to be tested.
   *
   * @var \Drupal\oauth2_server\OAuth2StorageInterface
   */
  protected $storage;

  /**
   * The test client.
   *
   * @var \Drupal\oauth2_server\ClientInterface
   */
  protected $client;

  /**
   * The redirect uri used on multiple locations.
   */
  protected $redirectUri;

  public function setUp() {
    parent::setUp();

    $this->redirectUri = $this->buildUrl('authorized', ['absolute' => TRUE]);

    /** @var \Drupal\oauth2_server\ServerInterface $server */
    $server = $this->container->get('entity.manager')->getStorage('oauth2_server')->create([
      'server_id' => 'test_server',
      'name' => 'Test Server',
      'settings' => [
        'default_scope' => '',
        'allow_implicit' => TRUE,
        'grant_types' => array(
          'authorization_code' => 'authorization_code',
          'client_credentials' => 'client_credentials',
          'refresh_token' => 'refresh_token',
          'password' => 'password',
        ),
        'always_issue_new_refresh_token' => TRUE,
        'advanced_settings' => [
          'require_exact_redirect_uri' => TRUE,
        ]
      ]
    ]);
    $server->save();

    /** @var \Drupal\oauth2_server\ClientInterface $client */
    $this->client = $this->container->get('entity.manager')->getStorage('oauth2_server_client')->create([
      'client_id' => $this->clientId,
      'server_id' => $server->id(),
      'name' => 'Test client',
      'unhashed_client_secret' => $this->clientSecret,
      'redirect_uri' => $this->redirectUri,
      'automatic_authorization' => TRUE,
    ]);
    $this->client->save();

    $this->storage = $this->container->get('oauth2_server.storage');
  }

  public function testCheckClientCredentials() {
    // Nonexistent client_id.
    $result = $this->storage->checkClientCredentials('fakeclient', 'testpass');
    $this->assertFalse($result, 'Invalid client credentials correctly detected.');

    // Invalid client_secret.
    $result = $this->storage->checkClientCredentials($this->clientId, 'invalidcredentials');
    $this->assertFalse($result, 'Invalid client_secret correctly detected.');

    // Valid credentials.
    $result = $this->storage->checkClientCredentials($this->clientId, $this->clientSecret);
    $this->assertTrue($result, 'Valid client credentials correctly detected.');

    // No client secret.
    $result = $this->storage->checkClientCredentials($this->clientId, '');
    $this->assertFalse($result, 'Empty client secret not accepted.');

    // Allow empty client secret, try again.
    $this->client->client_secret = '';
    $this->client->save();
    $result = $this->storage->checkClientCredentials($this->clientId, '');
    $this->assertTrue($result, 'Empty client secret accepted if none required.');

    // Try again with a NULL client secret. This should be accepted too.
    $result = $this->storage->checkClientCredentials($this->clientId, NULL);
    $this->assertTrue($result, 'Null client secret accepted if none required.');
  }

  public function testGetClientDetails() {
    // Nonexistent client_id.
    $details = $this->storage->getClientDetails('fakeclient');
    $this->assertFalse($details, 'Invalid client_id correctly detected.');

    // Valid client_id.
    $details = $this->storage->getClientDetails($this->clientId);
    $this->assertNotNull($details, 'Client details successfully returned.');
    $this->assertTrue(array_key_exists('client_id', $details), 'The "client_id" value is present in the client details.');
    $this->assertTrue(array_key_exists('client_secret', $details), 'The "client_secret" value is present in the client details.');
    $this->assertTrue(array_key_exists('redirect_uri', $details), 'The "redirect_uri" value is present in the client details.');
  }

  public function testAccessToken() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));

    $token = $this->storage->getAccessToken('newtoken');
    $this->assertFalse($token, 'Trying to load a nonexistent token is unsuccessful.');

    $expires = time() + 20;
    $success = $this->storage->setAccessToken('newtoken', $this->clientId, $user->id(), $expires);
    $this->assertTrue($success, 'A new access token has been successfully created.');

    // Verify the return format of getAccessToken().
    $token = $this->storage->getAccessToken('newtoken');
    $this->assertTrue($token, 'An access token was successfully returned.');
    $this->assertTrue(array_key_exists('access_token', $token), 'The "access_token" value is present in the token array.');
    $this->assertTrue(array_key_exists('client_id', $token), 'The "client_id" value is present in the token array.');
    $this->assertTrue(array_key_exists('user_id', $token), 'The "user_id" value is present in the token array.');
    $this->assertTrue(array_key_exists('expires', $token), 'The "expires" value is present in the token array.');
    $this->assertEqual($token['access_token'], 'newtoken', 'The "access_token" key has the expected value.');
    $this->assertEqual($token['client_id'], $this->clientId, 'The "client_id" key has the expected value.');
    $this->assertEqual($token['user_id'], $user->id(), 'The "user_id" key has the expected value.');
    $this->assertEqual($token['expires'], $expires, 'The "expires" key has the expected value.');

    // Update the token.
    $expires = time() + 42;
    $success = $this->storage->setAccessToken('newtoken', $this->clientId, $user->id(), $expires);
    $this->assertTrue($success, 'The access token was successfully updated.');

    $token = $this->storage->getAccessToken('newtoken');
    $this->assertTrue($token, 'An access token was successfully returned.');
    $this->assertEqual($token['expires'], $expires, 'The expires timestamp matches the new value.');
  }

  public function testSetRefreshToken() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));

    $token = $this->storage->getRefreshToken('refreshtoken');
    $this->assertFalse($token, 'Trying to load a nonexistent token is unsuccessful.');

    $expires = time() + 20;
    $success = $this->storage->setRefreshToken('refreshtoken', $this->clientId, $user->id(), $expires);
    $this->assertTrue($success, 'A new refresh token has been successfully created.');

    // Verify the return format of getRefreshToken().
    $token = $this->storage->getRefreshToken('refreshtoken');
    $this->assertTrue($token, 'A refresh token was successfully returned.');
    $this->assertTrue(array_key_exists('refresh_token', $token), 'The "refresh_token" value is present in the token array.');
    $this->assertTrue(array_key_exists('client_id', $token), 'The "client_id" value is present in the token array.');
    $this->assertTrue(array_key_exists('user_id', $token), 'The "user_id" value is present in the token array.');
    $this->assertTrue(array_key_exists('expires', $token), 'The "expires" value is present in the token array.');
    $this->assertEqual($token['refresh_token'], 'refreshtoken', 'The "refresh_token" key has the expected value.');
    $this->assertEqual($token['client_id'], $this->clientId, 'The "client_id" key has the expected value.');
    $this->assertEqual($token['user_id'], $user->id(), 'The "user_id" key has the expected value.');
    $this->assertEqual($token['expires'], $expires, 'The "expires" key has the expected value.');
  }

  public function testAuthorizationCode() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));

    $code = $this->storage->getAuthorizationCode('newcode');
    $this->assertFalse($code, 'Trying to load a nonexistent authorization code is unsuccessful.');

    $expires = time() + 20;
    $success = $this->storage->setAuthorizationCode('newcode', $this->clientId, $user->id(), 'http://example.com', $expires);
    $this->assertTrue($success, 'A new authorization code was successfully created.');

    // Verify the return format of getAuthorizationCode().
    $code = $this->storage->getAuthorizationCode('newcode');
    $this->assertTrue($code, 'An authorization code was successfully returned.');
    $this->assertTrue(array_key_exists('authorization_code', $code), 'The "authorization_code" value is present in the code array.');
    $this->assertTrue(array_key_exists('client_id', $code), 'The "client_id" value is present in the code array.');
    $this->assertTrue(array_key_exists('user_id', $code), 'The "user_id" value is present in the code array.');
    $this->assertTrue(array_key_exists('redirect_uri', $code), 'The "redirect_uri" value is present in the code array.');
    $this->assertTrue(array_key_exists('expires', $code), 'The "expires" value is present in the code array.');
    $this->assertEqual($code['authorization_code'], 'newcode', 'The "authorization_code" key has the expected value.');
    $this->assertEqual($code['client_id'], $this->clientId, 'The "client_id" key has the expected value.');
    $this->assertEqual($code['user_id'], $user->id(), 'The "user_id" key has the expected value.');
    $this->assertEqual($code['redirect_uri'], 'http://example.com', 'The "redirect_uri" key has the expected value.');
    $this->assertEqual($code['expires'], $expires, 'The "expires" key has the expected value.');

    // Change an existing code
    $expires = time() + 42;
    $success = $this->storage->setAuthorizationCode('newcode', $this->clientId, $user->id(), 'http://example.org', $expires);
    $this->assertTrue($success, 'The authorization code was successfully updated.');

    $code = $this->storage->getAuthorizationCode('newcode');
    $this->assertTrue($code, 'An authorization code was successfully returned.');
    $this->assertEqual($code['expires'], $expires, 'The expires timestamp matches the new value.');
  }

  public function testCheckUserCredentials() {
    $user = $this->drupalCreateUser(array('use oauth2 server'));

    // Correct credentials
    $result = $this->storage->checkUserCredentials($user->name->value, $user->pass_raw);
    $this->assertTrue($result, 'Valid user credentials correctly detected.');
    // Invalid username.
    $result = $this->storage->checkUserCredentials('fakeusername', $user->pass_raw);
    $this->assertFalse($result, 'Invalid username correctly detected.');
    // Invalid password.
    $result = $this->storage->checkUserCredentials($user->name->value, 'fakepass');
    $this->assertFalse($result, 'Invalid password correctly detected');
  }
}