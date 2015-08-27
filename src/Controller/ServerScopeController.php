<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Controller\ServerScopeController.
 */

namespace Drupal\oauth2_server\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\oauth2_server\ServerInterface;
use Drupal\oauth2_server\ScopeInterface;


/**
 * Provides block routines for oauth2 server's scope-specific routes.
 */
class ServerScopeController extends ControllerBase {
  /**
   * Return a list of scopes for a OAuth2 server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *   The server to display the scopes of.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response to send to the browser.
   */
  public function serverScopes(ServerInterface $oauth2_server) {
    return $this->entityManager()->getListBuilder('oauth2_server_scope')->render($oauth2_server);
  }

  /**
   * Returns the page title for an server's "Scopes" tab.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *   The server that is displayed.
   *
   * @return string
   *   The page title.
   */
  public function serverScopesTitle(ServerInterface $oauth2_server) {
    return $this->t('OAuth2 Server: %name scopes', array('%name' => $oauth2_server->label()));
  }

  /**
   * Returns the form for adding a scope to a server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *  The server the scope should belong to.
   *
   * @return array
   *  The renderable form.
   */
  public function serverAddScope(ServerInterface $oauth2_server) {
    $scope = $this->entityManager()->getStorage('oauth2_server_scope')->create(['server_id' => $oauth2_server->id()]);
    $form = $this->entityFormBuilder()->getForm($scope, 'add', ['oauth2_server' => $oauth2_server]);
    return $form;
  }

  /**
   * Returns the form for editing a scope to a server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *  The server the scope should belong to.
   *
   * @param \Drupal\oauth2_server\ScopeInterface $oauth2_server_scope
   *  The scope entity.
   *
   * @return array
   *  The renderable form.
   */
  public function serverEditScope(ServerInterface $oauth2_server, ScopeInterface $oauth2_server_scope) {
    $form = $this->entityFormBuilder()->getForm($oauth2_server_scope, 'edit', ['oauth2_server' => $oauth2_server]);
    return $form;
  }

  /**
   * Returns the form for deleting a scope to a server.
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *  The server the scope should belong to.
   *
   * @param \Drupal\oauth2_server\ScopeInterface $oauth2_server_scope
   *  The scope entity.
   * @return array
   *  The renderable form.
   */
  public function serverDeleteScope(ServerInterface $oauth2_server, ScopeInterface $oauth2_server_scope) {
    $form = $this->entityFormBuilder()->getForm($oauth2_server_scope, 'delete', ['oauth2_server' => $oauth2_server]);
    return $form;
  }
}
