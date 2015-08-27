<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Form\ScopeDeleteConfirmForm.
 */

namespace Drupal\oauth2_server\Form;

use Drupal\Core\Entity\EntityConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;

/**
 * Defines a confirm form for deleting a scope.
 */
class ScopeDeleteConfirmForm extends EntityConfirmFormBase {

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    return $this->t('Are you sure you want to delete the OAuth2 server scope %name?', array('%name' => $this->entity->label()));
  }

  /**
   * {@inheritdoc}
   */
  public function getDescription() {
    return $this->t('Deleting a scope will disable all connectivity to the scope.');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelUrl() {
    return new Url('entity.oauth2_server.scopes', ['oauth2_server' => $this->entity->server_id]);
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
    drupal_set_message($this->t('The OAuth2 server scope %name has been deleted.', array('%name' => $this->entity->label())));
    $form_state->setRedirect('entity.oauth2_server.scopes', ['oauth2_server' => $this->entity->server_id]);
  }

}
