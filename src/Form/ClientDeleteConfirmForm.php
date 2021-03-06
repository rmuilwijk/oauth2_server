<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Form\ClientDeleteConfirmForm.
 */

namespace Drupal\oauth2_server\Form;

use Drupal\Core\Entity\EntityConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;

/**
 * Defines a confirm form for deleting a client.
 */
class ClientDeleteConfirmForm extends EntityConfirmFormBase {

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    return $this->t('Are you sure you want to delete the OAuth2 server client %name?', array('%name' => $this->entity->label()));
  }

  /**
   * {@inheritdoc}
   */
  public function getDescription() {
    return $this->t('Deleting a client will disable all connectivity to it.');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelUrl() {
    return new Url('entity.oauth2_server.clients', ['oauth2_server' => $this->entity->server_id]);
  }

  /**
   * {@inheritdoc}
   */
  public function getConfirmText() {
    return $this->t('Delete');
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->entity->delete();
    drupal_set_message($this->t('The OAuth2 server client %name has been deleted.', array('%name' => $this->entity->label())));
    $form_state->setRedirect('entity.oauth2_server.clients', ['oauth2_server' => $this->entity->server_id]);
  }

}
