<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Controller\ServerClientController.
 */

namespace Drupal\oauth2_server\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\oauth2_server\ServerInterface;
use Drupal\oauth2_server\ClientInterface;


/**
 * Provides block routines for oauth2 server's client-specific routes.
 */
class ServerClientController extends ControllerBase {
  /**
   * Return a list of clients for a OAuth2 server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *   The server to display the clients of.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response to send to the browser.
   */
  public function serverClients(ServerInterface $oauth2_server) {
    return $this->entityManager()->getListBuilder('oauth2_server_client')->render($oauth2_server);
  }

  /**
   * Returns the page title for an server's "Clients" tab.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *   The server that is displayed.
   *
   * @return string
   *   The page title.
   */
  public function serverClientsTitle(ServerInterface $oauth2_server) {
    return $this->t('OAuth2 Server: %name clients', array('%name' => $oauth2_server->label()));
  }

  /**
   * Returns the form for adding a client to a server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *  The server the client should belong to.
   *
   * @return array
   *  The renderable form.
   */
  public function serverAddClient(ServerInterface $oauth2_server) {
    $client = $this->entityManager()->getStorage('oauth2_server_client')->create(['server_id' => $oauth2_server->id()]);
    $form = $this->entityFormBuilder()->getForm($client, 'add', ['oauth2_server' => $oauth2_server]);
    return $form;
  }

  /**
   * Returns the form for editing a client to a server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *  The server the client should belong to.
   *
   * @param \Drupal\oauth2_server\ClientInterface $oauth2_server_client
   *  The client entity.
   *
   * @return array
   *  The renderable form.
   */
  public function serverEditClient(ServerInterface $oauth2_server, ClientInterface $oauth2_server_client) {
    $form = $this->entityFormBuilder()->getForm($oauth2_server_client, 'edit', ['oauth2_server' => $oauth2_server]);
    return $form;
  }

  /**
   * Returns the form for deleting a client to a server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *  The server the client should belong to.
   *
   * @param \Drupal\oauth2_server\ClientInterface $oauth2_server_client
   *  The client entity.
   *
   * @return array
   *  The renderable form.
   */
  public function serverDeleteClient(ServerInterface $oauth2_server, ClientInterface $oauth2_server_client) {
    $form = $this->entityFormBuilder()->getForm($oauth2_server_client, 'delete', ['oauth2_server' => $oauth2_server]);
    return $form;
  }
}
