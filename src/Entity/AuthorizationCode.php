<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\Entity\AuthorizationCode.
 */

namespace Drupal\oauth2_server\Entity;

use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\Core\Field\FieldStorageDefinitionInterface;
use Drupal\oauth2_server\AuthorizationCodeInterface;

/**
 * Defines the OAuth2 server authorization code entity.
 *
 * @ContentEntityType(
 *   id = "oauth2_server_authorization_code",
 *   label = @Translation("OAuth2 Server Authorization Code"),
 *   base_table = "oauth2_server_authorization_code",
 *   admin_permission = "administer oauth2 server",
 *   fieldable = FALSE,
 *   translatable = FALSE,
 *   entity_keys = {
 *     "id" = "code_id",
 *     "label" = "uid"
 *   }
 * )
 */
class AuthorizationCode extends ContentEntityBase implements AuthorizationCodeInterface {
  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type) {
    $fields['code_id'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Code ID'))
      ->setDescription(t('Primary key: numeric code id.'));

    $fields['client_id'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('OAuth2 Server Client'))
      ->setDescription(t('The OAuth2 Client of the client.'))
      ->setSettings(array('target_type' => 'oauth2_server_client'));

    $fields['uid'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('User'))
      ->setDescription(t('The user of the resource owner.'))
      ->setSettings(array('target_type' => 'user'));

    $fields['code'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Code'))
      ->setDescription(t('The authorization code.'))
      ->setTranslatable(FALSE)
      ->setSettings(array(
        'not null' => TRUE,
        'max_length' => 255,
        'text_processing' => 0,
      ));

    $fields['scopes'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('Scopes'))
      ->setDescription(t('The scopes of the authorization code.'))
      ->setSettings(array('target_type' => 'oauth2_server_scope'))
      ->setCardinality(FieldStorageDefinitionInterface::CARDINALITY_UNLIMITED);

    $fields['redirect_uri'] = BaseFieldDefinition::create('uri')
      ->setLabel(t('Redirect Uri'))
      ->setDescription(t('The absolute URI to redirect to after authorization.'));

    $fields['expires'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(t('Expires'))
      ->setDescription(t('The Unix timestamp when the token expires.'));

    $fields['id_token'] = BaseFieldDefinition::create('string_long')
      ->setLabel(t('ID Token'))
      ->setDescription(t('The id token, if OpenID Connect was used.'))
      ->setTranslatable(FALSE)
      ->setSettings(array(
        'text_processing' => 0,
        'case_sensitive' => FALSE,
      ));

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
