<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\TokenInterface.
 */

namespace Drupal\oauth2_server;

use Drupal\Core\Entity\ContentEntityInterface;

/**
 * Defines the interface for token entities.
 */
interface TokenInterface extends ContentEntityInterface {
  /**
   * Return the user the token belongs to.
   *
   * @return \Drupal\user\UserInterface;
   *   The user object or FALSE.
   */
  public function getUser();

  /**
   * Return the client the token belongs to.
   *
   * @return \Drupal\oauth2_server\ClientInterface;
   *   The client object or FALSE.
   */
  public function getClient();
}
