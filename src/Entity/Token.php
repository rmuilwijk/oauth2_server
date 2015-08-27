<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\Entity\Token.
 */

namespace Drupal\oauth2_server\Entity;

use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\Core\Field\FieldStorageDefinitionInterface;
use Drupal\oauth2_server\TokenInterface;

/**
 * Defines the OAuth2 server token entity.
 *
 * @ContentEntityType(
 *   id = "oauth2_server_token",
 *   label = @Translation("OAuth2 Server Token"),
 *   base_table = "oauth2_server_token",
 *   admin_permission = "administer oauth2 server",
 *   fieldable = FALSE,
 *   translatable = FALSE,
 *   entity_keys = {
 *     "id" = "token_id",
 *     "label" = "token"
 *   }
 * )
 */
class Token extends ContentEntityBase implements TokenInterface {
  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type) {
    $fields['token_id'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Code ID'))
      ->setDescription(t('Primary key: numeric token id.'));

    $fields['client_id'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('OAuth2 Server Client'))
      ->setDescription(t('The OAuth2 Client of the client.'))
      ->setSettings(array('target_type' => 'oauth2_server_client'));

    $fields['uid'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('User'))
      ->setDescription(t('The user of the resource owner.'))
      ->setSettings(array('target_type' => 'user'));

    $fields['type'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Type'))
      ->setDescription(t('The type of the token (access, refresh).'))
      ->setTranslatable(FALSE)
      ->setSettings(array(
        'not null' => TRUE,
        'max_length' => 255,
        'text_processing' => 0,
      ));

    $fields['token'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Token'))
      ->setDescription(t('The token.'))
      ->setTranslatable(FALSE)
      ->setSettings(array(
        'not null' => TRUE,
        'max_length' => 255,
        'text_processing' => 0,
      ));

    $fields['scopes'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('Scopes'))
      ->setDescription(t('The scopes of the token.'))
      ->setSettings(array('target_type' => 'oauth2_server_scope'))
      ->setCardinality(FieldStorageDefinitionInterface::CARDINALITY_UNLIMITED);

    $fields['expires'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(t('Expires'))
      ->setDescription(t('The Unix timestamp when the token expires.'));

    $fields['last_access'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(t('Last Access'))
      ->setDescription(t('The Unix timestamp when the token was last used.'));

    return $fields;
  }

  /**
   * {@inheritdoc}
   */
  public function getUser() {
    if ($uid = $this->uid->getValue()) {
      return $this->entityManager()->getStorage('user')->load($uid[0]['target_id']);
    }

    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function getClient() {
    if ($client_id = $this->client_id->getValue()) {
      return $this->entityManager()->getStorage('oauth2_server_client')->load($client_id[0]['target_id']);
    }

    return FALSE;
  }
}
