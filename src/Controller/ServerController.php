<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Controller\ServerController.
 */

namespace Drupal\oauth2_server\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\oauth2_server\ServerInterface;


/**
 * Provides block routines for oauth2 server-specific routes.
 */
class ServerController extends ControllerBase {
  /**
   * Enables a OAuth2 server without a confirmation form.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *   The server to be enabled.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response to send to the browser.
   */
  public function serverBypassEnable(ServerInterface $oauth2_server) {
    $oauth2_server->setStatus(TRUE)->save();

    // Notify the user about the status change.
    drupal_set_message($this->t('The OAuth2 server %name has been enabled.', array('%name' => $oauth2_server->label())));

    return $this->redirect('oauth2_server.overview');
  }
}
