<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\Entity\Server.
 */

namespace Drupal\oauth2_server\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\oauth2_server\ServerInterface;

/**
 * Defines the OAuth2 server entity.
 *
 * @ConfigEntityType(
 *   id = "oauth2_server",
 *   label = @Translation("OAuth2 Server"),
 *   handlers = {
 *     "storage" = "Drupal\Core\Config\Entity\ConfigEntityStorage",
 *     "view_builder" = "Drupal\Core\Entity\EntityViewBuilder",
 *     "list_builder" = "Drupal\oauth2_server\ServerListBuilder",
 *     "form" = {
 *       "add" = "Drupal\oauth2_server\Form\ServerForm",
 *       "edit" = "Drupal\oauth2_server\Form\ServerForm",
 *       "default" = "Drupal\oauth2_server\Form\ServerForm",
 *       "delete" = "Drupal\oauth2_server\Form\ServerDeleteConfirmForm",
 *       "disable" = "Drupal\oauth2_server\Form\ServerDisableConfirmForm"
 *     },
 *   },
 *   config_prefix = "server",
 *   admin_permission = "administer oauth2 server",
 *   entity_keys = {
 *     "id" = "server_id",
 *     "label" = "name",
 *     "uuid" = "uuid",
 *     "status" = "status"
 *   },
 *   links = {
 *     "add-form" = "/admin/structure/oauth2-servers/add-server",
 *     "edit-form" = "/admin/structure/oauth2-servers/manage/{oauth2_server}/edit",
 *     "delete-form" = "/admin/structure/oauth2-servers/manage/{oauth2_server}/delete",
 *     "disable" = "/admin/structure/oauth2-servers/manage/{oauth2_server}/disable",
 *     "enable" = "/admin/structure/oauth2-servers/manage/{oauth2_server}/enable",
 *     "scopes" = "/admin/structure/oauth2-servers/manage/{oauth2_server}/scopes",
 *     "clients" = "/admin/structure/oauth2-servers/manage/{oauth2_server}/clients",
 *   },
 *   config_export = {
 *     "server_id",
 *     "name",
 *     "settings",
 *     "status",
 *     "module"
 *   }
 * )
 */
class Server extends ConfigEntityBase implements ServerInterface {
  /**
   * The machine name of this server.
   *
   * @var string
   */
  protected $server_id;

  /**
   * The human-readable name of this server.
   *
   * @var string
   */
  protected $name;

  /**
   * An array of settings.
   *
   * @var array
   */
  public $settings = array(
    'default_scope' => '',
    'enforce_state' => TRUE,
    'allow_implicit' => FALSE,
    'use_openid_connect' => FALSE,
    'use_crypto_tokens' => FALSE,
    'store_encrypted_token_string' => FALSE,
    'grant_types' => array(
      'authorization_code' => 'authorization_code',
      'refresh_token' => 'refresh_token',
    ),
    'advanced_settings' => array(
      'access_lifetime' => 3600,
      'id_lifetime' => 3600,
      'refresh_token_lifetime' => 1209600,
      'require_exact_redirect_uri' => TRUE,
    ),
  );

  /**
   * The name of the providing module if the server has been defined in code.
   *
   * @var string
   */
  protected $module;

  /**
   * {@inheritdoc}
   */
  public function id() {
    return isset($this->server_id) ? $this->server_id : NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function label() {
    return isset($this->name) ? $this->name : NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function postSave(EntityStorageInterface $storage, $update = TRUE) {
    parent::postSave($storage, $update);

    $old_settings = isset($this->original) ? $this->original->settings : array();
    $previous_value = !empty($old_settings['use_openid_connect']);
    $current_value = !empty($this->settings['use_openid_connect']);

    if (!$previous_value && $current_value) {
      $openid_scopes = array(
        'openid' => format_string('Know who you are on @site', array('@site' => \Drupal::config('system.site')->get('name'))),
        'offline_access' => "Access the API when you're not present.",
        'email' => 'View your email address.',
        'profile' => 'View basic information about your account.',
      );
      foreach ($openid_scopes as $id => $description) {
        $scope = $this->entityManager()->getStorage('oauth2_server_scope')->load($this->id() . '_' . $id);
        if (!$scope) {
          $scope = \Drupal\oauth2_server\Entity\Scope::create([
            'scope_id' => $id,
            'server_id' => $this->id(),
            'description' => $description,
          ]);
          $scope->save();
        }
      }
    }
    // If OpenID Connect was just disabled, delete its scopes.
    if ($previous_value && !$current_value) {
      $scope_names = array('openid', 'offline_access', 'email', 'profile');
      $scopes = $this->entityManager()->getStorage('oauth2_server_scope')->loadByProperties(['server_id' => $this->id(), 'scope_id' => $scope_names]);
      foreach ($scopes as $scope) {
        $scope->delete();
      }
      // If we just deleted a default scope, update the server.
      if (in_array($this->settings['default_scope'], $scope_names)) {
        $this->settings['default_scope'] = '';
        $this->save();
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function delete() {
    parent::delete();

    // Clean up scopes.
    $scopes = $this->entityManager()->getStorage('oauth2_server_scope')->loadByProperties(['server_id' => $this->id()]);
    foreach ($scopes as $scope) {
      $scope->delete();
    }

    // Clean up clients.
    $clients = $this->entityManager()->getStorage('oauth2_server_client')->loadByProperties(['server_id' => $this->id()]);
    foreach ($clients as $client) {
      $client->delete();
    }
  }
}
