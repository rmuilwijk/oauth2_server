<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\ClientInterface.
 */

namespace Drupal\oauth2_server;

use Drupal\Core\Config\Entity\ConfigEntityInterface;

/**
 * Defines the interface for client entities.
 */
interface ClientInterface extends ConfigEntityInterface {
  /**
   * Returns the server the client belongs to.
   *
   * @return \Drupal\oauth2_server\ServerInterface
   *   Returns the server object the client belongs to.
   */
  public function getServer();

  /**
   * Hash a client secret for storage.
   * Make sure this uses the same algorithm as checkClientCredentials form the \OAuth2\StorageInterface.
   *
   * @param string $client_secret
   *   The raw secret.
   *
   * @return string
   *   The hashed secret.
   */
  function hashClientSecret($client_secret);
}
