<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Form\ClientForm.
 */

namespace Drupal\oauth2_server\Form;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\Entity\ConfigEntityStorage;
use Drupal\Core\Entity\EntityForm;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Entity\Query\QueryFactory;
use Drupal\Core\Url;
use Drupal\Core\Form\FormState;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\oauth2_server\Utility;

/**
 * Provides form for client instance forms.
 */
class ClientForm extends EntityForm {

  /**
   * The client entity.
   *
   * @var \Drupal\oauth2_server\ClientInterface
   */
  protected $entity;

  /**
   * The client storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $storage;

  /**
   * The entity query factory.
   *
   * @var \Drupal\Core\Entity\Query\QueryFactory
   */
  protected $entityQuery;

  /**
   * Constructs a ClientForm object.
   *
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager.
   */
  public function __construct(EntityManagerInterface $entity_manager, QueryFactory $entity_query) {
    $this->storage = $entity_manager->getStorage('oauth2_server_client');
    $this->entityQuery = $entity_query;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('entity.manager'),
      $container->get('entity.query')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function form(array $form, FormStateInterface $form_state) {
    $client = $this->entity;

    $server = $form_state->get('oauth2_server');
    if (!$server) {
      throw new \Exception('OAuth2 server was not set');
    }

    $form['#tree'] = TRUE;
    $form['server_id'] = array(
      '#type' => 'value',
      '#value' => $server->id(),
    );

    $form['name'] = array(
      '#title' => $this->t('Label'),
      '#type' => 'textfield',
      '#default_value' => $client->name,
      '#description' => $this->t('The human-readable name of this client.'),
      '#required' => TRUE,
      '#weight' => -50,
    );
    $form['client_id'] = array(
      '#title' => $this->t('Client ID'),
      '#type' => 'machine_name',
      '#default_value' => $client->id(),
      '#required' => TRUE,
      '#weight' => -40,
      '#machine_name' => array(
        'exists' => array($this, 'exists'),
      ),
    );
    $form['require_client_secret'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Require a client secret'),
      '#default_value' => !empty($client->isNew()) || !empty($client->client_secret),
      '#weight' => -35,
    );
    $grant_types = array_filter($client->settings['override_grant_types'] ? $client->settings['grant_types'] : $server->settings['grant_types']);
    $jwt_bearer_enabled = isset($grant_types['urn:ietf:params:oauth:grant-type:jwt-bearer']);
    $form['client_secret'] = array(
      '#title' => $this->t('Client secret'),
      '#type' => 'password',
      '#weight' => -30,
      // Hide this field if only JWT bearer is enabled, since it doesn't use it.
      '#access' => (count($grant_types) != 1 || !$jwt_bearer_enabled),
      '#states' => array(
        'required' => array(
          'input[name="require_client_secret"]' => array('checked' => TRUE),
        ),
        'visible' => array(
          'input[name="require_client_secret"]' => array('checked' => TRUE),
        ),
      ),
    );
    if (!empty($client->client_secret)) {
      $form['client_secret']['#description'] = $this->t('Leave this blank, and leave "Require a client secret" checked, to use the previously saved secret.');
      unset($form['client_secret']['#states']['required']);
    }
    $form['public_key'] = array(
      '#title' => $this->t('Public key'),
      '#type' => 'textarea',
      '#default_value' => $client->public_key,
      '#required' => TRUE,
      '#description' => $this->t('Used to decode the JWT when the %JWT grant type is used.', array('%JWT' => t('JWT bearer'))),
      '#weight' => -20,
      // Show the field if JWT bearer is enabled, other grant types don't use it.
      '#access' => $jwt_bearer_enabled,
    );

    $form['redirect_uri'] = array(
      '#title' => $this->t('Redirect URIs'),
      '#type' => 'textarea',
      '#default_value' => $client->redirect_uri,
      '#description' => $this->t('The absolute URIs to validate against. Enter one value per line.'),
      '#required' => TRUE,
      '#weight' => -10,
    );

    $form['automatic_authorization'] = array(
      '#title' => $this->t('Automatically authorize this client'),
      '#type' => 'checkbox',
      '#default_value' => $client->automatic_authorization,
      '#description' => $this->t('This will cause the authorization form to be skipped. <b>Warning:</b> Give to trusted clients only!'),
      '#weight' => 39,
    );

    $form['settings'] = array(
      '#type' => 'fieldset',
      '#title' => $this->t('Advanced settings'),
      '#collapsible' => TRUE,
      '#weight' => 40,
    );
    $form['settings']['override_grant_types'] = array(
      '#title' => $this->t('Override available grant types'),
      '#type' => 'checkbox',
      '#default_value' => !empty($client->settings['override_grant_types']),
    );
    $form['settings']['allow_implicit'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Allow the implicit flow'),
      '#description' => $this->t('Allows clients to receive an access token without the need for an authorization request token.'),
      '#default_value' => !empty($client->settings['allow_implicit']),
      '#states' => array(
        'visible' => array(
          '#edit-settings-override-grant-types' => array('checked' => TRUE),
        ),
      ),
    );
    $grant_types = Utility::getGrantTypes();
    // Prepare a list of available grant types.
    $grant_type_options = array();
    foreach ($grant_types as $type => $grant_type) {
      $grant_type_options[$type] = $grant_type['name'];
    }
    $form['settings']['grant_types'] = array(
      '#type' => 'checkboxes',
      '#title' => t('Enabled grant types'),
      '#options' => $grant_type_options,
      '#default_value' => $client->settings['grant_types'],
      '#states' => array(
        'visible' => array(
          '#edit-settings-override-grant-types' => array('checked' => TRUE),
        ),
      ),
    );
    // Add any grant type specific settings.
    foreach ($grant_types as $type => $grant_type) {
      // Merge-in any provided defaults.
      if (isset($grant_type['default settings'])) {
        $client->settings += $grant_type['default settings'];
      }
      // Add the form elements.
      if (isset($grant_type['settings callback'])) {
        $dom_ids = array();
        $dom_ids[] = 'edit-settings-override-grant-types';
        $dom_ids[] = 'edit-settings-grant-types-' . str_replace('_', '-', $type);
        $form['settings'] += $grant_type['settings callback']($client->settings, $dom_ids);
      }
    }

    return parent::form($form, $form_state);
  }

  /**
   * Determines if the client entity already exists.
   *
   * @param string $client_id
   *   The client ID.
   *
   * @return bool
   *   TRUE if the client exists, FALSE otherwise.
   */
  public function exists($client_id) {
    $entity = $this->entityQuery->get('oauth2_server_client')
      ->condition('client_id', $client_id)
      ->execute();
    return (bool) $entity;
  }


  /**
   * {@inheritdoc}
   */
  protected function actions(array $form, FormStateInterface $form_state) {
    $actions = parent::actions($form, $form_state);
    $actions['submit']['#value'] = $this->t('Save client');

    return $actions;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    parent::validateForm($form, $form_state);

    $client_secret = '';
    if (!empty($form_state->getValue('require_client_secret'))) {
      if (!empty($form_state->getValue('client_secret'))) {
        $client_secret = $this->entity->hashClientSecret($form_state->getValue('client_secret'));
        if (!$client_secret) {
          throw new \Exception("Failed to hash client secret");
        }
      }
      elseif (!empty($this->entity->client_secret)) {
        $client_secret = $this->entity->client_secret;
      }
      else {
        $form_state->setErrorByName('client_secret', $this->t('A client secret is required.'));
      }
    }
    $form_state->setValue('client_secret',$client_secret);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);
    drupal_set_message($this->t('The client configuration has been saved.'));
    $form_state->setRedirect('entity.oauth2_server.clients', ['oauth2_server' => $form_state->get('oauth2_server')->id()]);
  }
}
