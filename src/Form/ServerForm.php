<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Form\ServerForm.
 */

namespace Drupal\oauth2_server\Form;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\Entity\ConfigEntityStorage;
use Drupal\Core\Entity\EntityForm;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Url;
use Drupal\Core\Form\FormState;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\oauth2_server\Utility;

/**
 * Provides form for server instance forms.
 */
class ServerForm extends EntityForm {

  /**
   * The server entity.
   *
   * @var \Drupal\oauth2_server\ServerInterface
   */
  protected $entity;

  /**
   * The server storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $storage;

  /**
   * Constructs a ServerForm object.
   *
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager.
   */
  public function __construct(EntityManagerInterface $entity_manager) {
    $this->storage = $entity_manager->getStorage('oauth2_server');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('entity.manager')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function form(array $form, FormStateInterface $form_state) {
    $server = $this->entity;

    $form['#title'] = $this->t('OAuth2 Server: %label edit', array('%label' => $server->label()));

    $form['#tree'] = TRUE;
    $form['name'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Server name'),
      '#description' => $this->t('Enter the displayed name for the server.'),
      '#default_value' => $server->label(),
      '#required' => TRUE,
    );
    $form['server_id'] = array(
      '#type' => 'machine_name',
      '#default_value' => !$server->isNew() ? $server->id() : '',
      '#maxlength' => 50,
      '#required' => TRUE,
      '#machine_name' => array(
        'exists' => array($this->storage, 'load'),
        'source' => array('name'),
      ),
    );
    $form['status'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Enabled'),
      '#description' => $this->t('Only enabled servers can be used for OAuth2.'),
      '#default_value' => $server->status(),
    );

    $form['settings'] = array(
      '#type' => 'fieldset',
      '#title' => t('Settings'),
    );
    $form['settings']['enforce_state'] = array(
      '#type' => 'value',
      '#value' => $server->settings['enforce_state'],
    );
    // The default scope is actually edited from the Scope UI to avoid showing
    // a select box with potentially thousands of options here.
    $form['settings']['default_scope'] = array(
      '#type' => 'value',
      '#value' => $server->settings['default_scope'],
    );
    $form['settings']['allow_implicit'] = array(
      '#type' => 'checkbox',
      '#title' => t('Allow the implicit flow'),
      '#description' => t('Allows clients to receive an access token without the need for an authorization request token.'),
      '#default_value' => !empty($server->settings['allow_implicit']),
    );
    $form['settings']['use_openid_connect'] = array(
      '#type' => 'checkbox',
      '#title' => t('Use OpenID Connect'),
      '#description' => t("Strongly recommended for login providers."),
      '#default_value' => !empty($server->settings['use_openid_connect']),
      '#access' => extension_loaded('openssl'),
    );
    $documentation_link = \Drupal::l('documentation', Url::fromUri('https://www.drupal.org/node/1254698'));
    $form['settings']['use_crypto_tokens'] = array(
      '#type' => 'checkbox',
      '#title' => t('Use JWT Access Tokens'),
      '#description' => t("Sends encrypted JWT access tokens that aren't stored in the database. See the !documentation for more details.", array('!documentation' => $documentation_link)),
      '#default_value' => !empty($server->settings['use_crypto_tokens']),
      '#access' => extension_loaded('openssl'),
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
      '#default_value' => $server->settings['grant_types'],
    );
    // Add any grant type specific settings.
    foreach ($grant_types as $type => $grant_type) {
      // Merge-in any provided defaults.
      if (isset($grant_type['default settings'])) {
        $server->settings += $grant_type['default settings'];
      }
      // Add the form elements.
      if (isset($grant_type['settings callback'])) {
        $dom_ids = array();
        $dom_ids[] = 'edit-settings-grant-types-' . str_replace('_', '-', $type);
        $form['settings'] += $grant_type['settings callback']($server->settings, $dom_ids);
      }
    }

    $form['settings']['advanced_settings'] = array(
      '#type' => 'fieldset',
      '#title' => t('Advanced settings'),
      '#collapsible' => TRUE,
      '#collapsed' => TRUE,
    );
    $form['settings']['advanced_settings']['access_lifetime'] = array(
      '#type' => 'textfield',
      '#title' => t('Access token lifetime'),
      '#description' => t('The number of seconds the access token will be valid for.'),
      '#default_value' => $server->settings['advanced_settings']['access_lifetime'],
      '#size' => 11,
    );
    $form['settings']['advanced_settings']['id_lifetime'] = array(
      '#type' => 'textfield',
      '#title' => t('ID token lifetime'),
      '#description' => t('The number of seconds the ID token will be valid for.'),
      '#default_value' => $server->settings['advanced_settings']['id_lifetime'],
      '#size' => 11,
      '#states' => array(
        'visible' => array(
          '#edit-settings-use-openid-connect' => array('checked' => TRUE),
        ),
      ),
    );
    $form['settings']['advanced_settings']['refresh_token_lifetime'] = array(
      '#type' => 'textfield',
      '#title' => t('Refresh token lifetime'),
      '#description' => t('The number of seconds the refresh token will be valid for. 0 for forever.'),
      '#default_value' => $server->settings['advanced_settings']['refresh_token_lifetime'],
      '#size' => 11,
    );
    $form['settings']['advanced_settings']['require_exact_redirect_uri'] = array(
      '#type' => 'checkbox',
      '#title' => t('Require exact redirect uri'),
      '#description' => t("Require the redirect url to be an exact match of the client's redirect url
    If not enabled, the redirect url in the request can contain additional segments, such as a query string."),
      '#default_value' => isset($server->settings['advanced_settings']['require_exact_redirect_uri']) ? $server->settings['advanced_settings']['require_exact_redirect_uri'] : TRUE,
    );

    return parent::form($form, $form_state);
  }

  /**
   * Provides a settings form for the refresh_token grant type.
   */
  public static function refreshTokenSettings($config, $dom_ids = array()) {
    $form = array();
    $form['always_issue_new_refresh_token'] = array(
      '#type' => 'checkbox',
      '#title' => t('Always issue a new refresh token after the existing one has been used'),
      '#default_value' => $config['always_issue_new_refresh_token'],
    );
    $form['unset_refresh_token_after_use'] = array(
      '#type' => 'checkbox',
      '#title' => t('Unset (delete) the refresh token after it has been used'),
      '#default_value' => $config['unset_refresh_token_after_use'],
    );
    foreach ($dom_ids as $dom_id) {
      $form['always_issue_new_refresh_token']['#states']['visible']['#' . $dom_id]['checked'] = TRUE;
      $form['unset_refresh_token_after_use']['#states']['visible']['#' . $dom_id]['checked'] = TRUE;
    }

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  protected function actions(array $form, FormStateInterface $form_state) {
    $actions = parent::actions($form, $form_state);
    $actions['submit']['#value'] = $this->t('Save server');

    return $actions;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    parent::validateForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);

    drupal_set_message($this->t('The server configuration has been saved.'));
    $form_state->setRedirect('oauth2_server.overview');
  }
}
