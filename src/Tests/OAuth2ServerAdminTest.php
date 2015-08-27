<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Tests\OAuth2ServerAdminTest.
 */


namespace Drupal\oauth2_server\Tests;

use Drupal\Core\Url;
use Drupal\simpletest\WebTestBase;
use Drupal\oauth2_server\ClientInterface;


/**
 * Tests oauth2 server.
 *
 * @group oauth2_server
 */
class OAuth2ServerAdminTest extends WebTestBase {
  /**
   * Modules to install.
   *
   * @var array
   */
  public static $modules = array('oauth2_server');

  public function testEditingClientSecret() {
    /** @var \Drupal\Core\Entity\EntityManagerInterface $entity_manager */
    $entity_manager = $this->container->get('entity.manager');

    /** @var \Drupal\Core\Password\PasswordInterface $password_hasher */
    $password_hasher = $this->container->get('password');

    $account = $this->drupalCreateUser(array('administer oauth2 server'));
    $this->drupalLogin($account);

    $server_id = strtolower($this->randomMachineName());

    // Create a server in the UI.
    $this->drupalPostForm(new Url('entity.oauth2_server.add_form'), array(
      'name' => $this->randomString(),
      'server_id' => $server_id,
    ), t('Save server'));

    // Create a client of the server in the UI, with a random secret.
    $client_id = strtolower($this->randomMachineName());
    $secret = $this->randomString(32);
    $this->drupalPostForm(new Url('entity.oauth2_server.clients.add_form', ['oauth2_server' => $server_id ]), array(
      'name' => $this->randomString(),
      'client_id' => $client_id,
      'redirect_uri' => 'http://localhost',
      'require_client_secret' => TRUE,
      'client_secret' => $secret,
    ), t('Save client'));

    // Test that the raw secret does not match the saved (hashed) one.
    $client = $entity_manager->getStorage('oauth2_server_client')->load($client_id);
    $this->assertNotEqual($secret, $client->client_secret, 'Raw secret does not match hashed secret.');

    // Test that the secret can be matched.
    $this->assertTrue($password_hasher->check($secret, $client->client_secret), 'Hashes match for known secret and stored secret.');

    // Edit the client, and do not set a new secret. It should stay the same.
    $old_hashed_secret = $client->client_secret;
    $this->updateClient($client, array(
      'name' => $this->randomString(),
    ));
    $entity_manager->getStorage('oauth2_server_client')->resetCache();
    $client = $entity_manager->getStorage('oauth2_server_client')->load($client_id);
    $this->assertEqual($old_hashed_secret, $client->client_secret, 'Secret is not changed accidentally when editing the client.');

    // Edit the client, and set an empty secret.
    $this->updateClient($client, array(
      'require_client_secret' => FALSE,
    ));
    $entity_manager->getStorage('oauth2_server_client')->resetCache();
    $client = $entity_manager->getStorage('oauth2_server_client')->load($client_id);
    $this->assertTrue($client->client_secret === '', 'Secret is set to empty if it is not required.');

    // Edit the client, and set a new, non-empty secret.
    $new_secret = $this->randomString(32);
    $this->updateClient($client, array(
      'require_client_secret' => TRUE,
      'client_secret' => $new_secret,
    ));
    $entity_manager->getStorage('oauth2_server_client')->resetCache();
    $client = $entity_manager->getStorage('oauth2_server_client')->load($client_id);
    $this->assertTrue($password_hasher->check($new_secret, $client->client_secret), 'Hashes match for new secret and stored secret.');
  }

  /**
   * Edit a client in the UI.
   *
   * @param \Drupal\oauth2_server\ClientInterface $client
   *   The client entity.
   * @param array $values
   *   New values.
   */
  protected function updateClient(ClientInterface $client, array $values) {
    $edit_uri = new Url('entity.oauth2_server.clients.edit_form', [
      'oauth2_server' => $client->getServer()->id(),
      'oauth2_server_client' => $client->id(),
    ]);

    $this->drupalPostForm($edit_uri, $values, t('Save client'));
  }
}
