<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Form\ServerDeleteConfirmForm.
 */

namespace Drupal\oauth2_server\Form;

use Drupal\Core\Entity\EntityConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;

/**
 * Defines a confirm form for deleting a server.
 */
class ServerDeleteConfirmForm extends EntityConfirmFormBase {

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    return $this->t('Are you sure you want to delete the OAuth2 server %name?', array('%name' => $this->entity->label()));
  }

  /**
   * {@inheritdoc}
   */
  public function getDescription() {
    return $this->t('Deleting a server will disable all its scopes and clients.');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelUrl() {
    return new Url('oauth2_server.overview');
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
    drupal_set_message($this->t('The OAuth2 server %name has been deleted.', array('%name' => $this->entity->label())));
    $form_state->setRedirect('oauth2_server.overview');
  }

}
