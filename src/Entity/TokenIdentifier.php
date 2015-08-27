<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\Entity\TokenIdentifier.
 */

namespace Drupal\oauth2_server\Entity;

use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;

/**
 * Defines the OAuth2 server JSON token identifier entity.
 *
 * @ContentEntityType(
 *   id = "oauth2_server_jti",
 *   label = @Translation("OAuth2 Server JTI"),
 *   base_table = "oauth2_server_jti",
 *   admin_permission = "administer oauth2 server",
 *   fieldable = FALSE,
 *   translatable = FALSE,
 *   entity_keys = {
 *     "id" = "jti_id",
 *     "label" = "jti"
 *   }
 * )
 */
class TokenIdentifier extends ContentEntityBase {
  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type) {
    $fields['jti_id'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('JTI ID'))
      ->setDescription(t('Primary key: numeric JTI id.'));

    $fields['client_id'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('OAuth2 Server Client'))
      ->setDescription(t('The OAuth2 Client of the client.'))
      ->setSettings(array('target_type' => 'oauth2_server_client'));

    $fields['subject'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Subject'))
      ->setDescription(t('The JWT subject, usually a username or email.'))
      ->setTranslatable(FALSE)
      ->setSettings(array(
        'not null' => TRUE,
        'max_length' => 255,
        'text_processing' => 0,
      ));

    $fields['jti'] = BaseFieldDefinition::create('string')
      ->setLabel(t('JTI'))
      ->setDescription(t('The JSON Token Identifier.'))
      ->setTranslatable(FALSE)
      ->setSettings(array(
        'not null' => TRUE,
        'max_length' => 255,
        'text_processing' => 0,
      ));

    $fields['expires'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(t('Expires'))
      ->setDescription(t('The Unix timestamp when the JTI expires.'));

    return $fields;
  }
}
