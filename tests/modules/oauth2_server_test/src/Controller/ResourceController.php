<?php

/**
 * @file
 * Contains \Drupal\oauth2_server_test\Controller\ResourceController.
 */

namespace Drupal\oauth2_server_test\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\RouteMatchInterface;
use OAuth2\ResponseInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Drupal\oauth2_server\Utility;

/**
 * Provides block routines for OAuth2 server test.
 */
class ResourceController extends ControllerBase {
  public function test(RouteMatchInterface $route_match, Request $request) {
    $scope = $route_match->getRawParameter('oauth2_server_scope');
    $response = Utility::checkAccess('test_server', $scope);
    if ($response instanceof ResponseInterface) {
      return $response;
    }
    else if (is_array($response)) {
      return new JsonResponse($response);
    }

    return new JsonResponse(['error' => 'No response']);
  }
}
