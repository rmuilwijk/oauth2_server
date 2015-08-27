<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\Entity\Scope.
 */

namespace Drupal\oauth2_server\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Config\Entity\ConfigEntityStorage;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\oauth2_server\ScopeInterface;

/**
 * Defines the OAuth2 scope entity.
 *
 * @ConfigEntityType(
 *   id = "oauth2_server_scope",
 *   label = @Translation("OAuth2 Server Scope"),
 *   handlers = {
 *     "storage" = "Drupal\Core\Config\Entity\ConfigEntityStorage",
 *     "list_builder" = "Drupal\oauth2_server\ScopeListBuilder",
 *     "form" = {
 *       "add" = "Drupal\oauth2_server\Form\ScopeForm",
 *       "edit" = "Drupal\oauth2_server\Form\ScopeForm",
 *       "default" = "Drupal\oauth2_server\Form\ScopeForm",
 *       "delete" = "Drupal\oauth2_server\Form\ScopeDeleteConfirmForm",
 *     },
 *   },
 *   config_prefix = "scope",
 *   admin_permission = "administer oauth2 server",
 *   entity_keys = {
 *     "id" = "id",
 *     "label" = "scope_id",
 *     "uuid" = "uuid",
 *   },
 *   config_export = {
 *     "id",
 *     "scope_id",
 *     "server_id",
 *     "description",
 *   }
 * )
 */
class Scope extends ConfigEntityBase implements ScopeInterface {
  /**
   * The id used for the scope.
   */
  protected $id;

  /**
   * The machine name of this scope.
   *
   * @var string
   */
  public $scope_id;

  /**
   * The machine name of this scope's server.
   *
   * @var string
   */
  public $server_id;

  /**
   * The loaded server.
   *
   * @var \Drupal\oauth2_server\ServerInterface $server;
   */
  protected $server;

  /**
   * The description of this scope.
   *
   * @var string
   */
  public $description;

  /**
   * {@inheritdoc}
   *
   * @return static
   *   The entity object.
   */
  public static function create(array $values = array()) {
    if (isset($values['server_id']) && isset($values['scope_id'])) {
      $values['id'] = $values['server_id'] . '_' . $values['scope_id'];
    }
    return parent::create($values);
  }

  /**
   * {@inheritdoc}
   */
  public function id() {
    if (!empty($this->server_id) && !empty($this->scope_id)) {
      return $this->server_id . '_' . $this->scope_id;
    }

    return isset($this->id) ? $this->id : NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function label() {
    return isset($this->scope_id) ? $this->scope_id : NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getServer() {
    if (!$this->server && $this->server_id) {
      $this->server = \Drupal::entityManager()->getStorage('oauth2_server')->load($this->server_id);
    }
    return $this->server;
  }

  /**
   * {@inheritdoc}
   */
  public function isDefault() {
    $server = $this->getServer();

    if (!empty($this->scope_id) && $server->settings['default_scope'] == $this->id()) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function preSave(EntityStorageInterface $storage) {
    $this->id = $this->server_id . '_' . $this->scope_id;
    parent::preSave($storage);
  }

  /**
   * {@inheritdoc}
   */
  public function __construct(array $values, $entity_type) {
    if (isset($values['server_id']) && isset($values['scope_id'])) {
      $values['id'] = $values['server_id'] . '_' . $values['scope_id'];
    }
    parent::__construct($values, $entity_type);
  }

  /**
   * {@inheritdoc}
   */
  public function __sleep() {
    $this->server = NULL;
    parent::__sleep();
  }
}
