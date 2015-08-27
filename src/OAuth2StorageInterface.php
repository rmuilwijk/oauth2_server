<?php
/**
 * @file
 * Contains \Drupal\oauth2_server\OAuth2StorageInterface.
 */

namespace Drupal\oauth2_server;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\UserCredentialsInterface;
use OAuth2\Storage\PublicKeyInterface;

interface OAuth2StorageInterface extends AuthorizationCodeInterface,
  AccessTokenInterface, ClientCredentialsInterface,
  JwtBearerInterface, RefreshTokenInterface,
  UserCredentialsInterface, UserClaimsInterface,
  PublicKeyInterface
{
}