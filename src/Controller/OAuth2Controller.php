<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\Controller\OAuth2Controller.
 */

namespace Drupal\oauth2_server\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Url;
use OAuth2\HttpFoundationBridge\Request as BridgeRequest;
use OAuth2\HttpFoundationBridge\Response as BridgeResponse;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Drupal\oauth2_server\OAuth2StorageInterface;
use Drupal\oauth2_server\ScopeUtility;
use Drupal\oauth2_server\Utility;

/**
 * Provides block routines for OAuth2.
 */
class OAuth2Controller extends ControllerBase {
  /**
   * The OAuth2Storage
   *
   * @var \Drupal\oauth2_server\OAuth2StorageInterface;
   */
  protected $storage;

  /**
   * Constructs a new \Drupal\oauth2_server\Controller\OAuth2Controller object.
   *
   * @param \Drupal\oauth2_server\OAuth2StorageInterface $oauth2_storage
   *   The OAuth2 storage object.
   */
  public function __construct(OAuth2StorageInterface $oauth2_storage) {
    $this->storage = $oauth2_storage;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('oauth2_server.storage')
    );
  }

  public function authorize(RouteMatchInterface $route_match, Request $request) {
    $this->moduleHandler()->invokeAll('oauth2_server_pre_authorize');
    $bridgeRequest = BridgeRequest::createFromRequest($request);

    if ($this->currentUser()->isAnonymous()) {
      $_SESSION['oauth2_server_authorize'] = $bridgeRequest;

      $url = new Url('user.login', [], ['query' => ['destination' => 'oauth2/authorize']]);
      $url->setAbsolute(TRUE);

      return new RedirectResponse($url->toString());
    }

    // A login happened. Create the request with parameters from the session.
    if (!empty($_SESSION['oauth2_server_authorize'])) {
      $bridgeRequest = $_SESSION['oauth2_server_authorize'];
    }

    $client = FALSE;
    if ($bridgeRequest->get('client_id')) {
      $clients = $this->entityManager()->getStorage('oauth2_server_client')->loadByProperties(['client_id' => $bridgeRequest->get('client_id')]);
      if ($clients) {
        /** @var \Drupal\oauth2_server\ClientInterface $client */
        $client = reset($clients);
      }
    }
    if (!$client) {
      return new JsonResponse(['error' => 'Client could not be found.'], JsonResponse::HTTP_NOT_FOUND);
    }

    // Initialize the server.
    $oauth2_server = Utility::startServer($client->getServer(), $this->storage);

    // Automatic authorization is enabled for this client. Finish authorization.
    // handleAuthorizeRequest() will call validateAuthorizeRequest().
    $response = new BridgeResponse();
    if ($client && $client->automatic_authorization) {
      unset($_SESSION['oauth2_server_authorize']);
      $oauth2_server->handleAuthorizeRequest($bridgeRequest, $response, TRUE, $this->currentUser()->id());
      return $response;
    }
    else {
      // Validate the request.
      if (!$oauth2_server->validateAuthorizeRequest($bridgeRequest, $response)) {
        // Clear the parameters saved in the session to avoid reusing them when
        // doing an other request while logged in.
        unset($_SESSION['oauth2_server_authorize']);
        return $response;
      }

      // Determine the scope for this request.
      $scope_util = new ScopeUtility($client->getServer());
      if (!$scope = $scope_util->getScopeFromRequest($bridgeRequest)) {
        $scope = $scope_util->getDefaultScope();
      }
      // Convert the scope string to a set of entities.
      $scope_names = explode(' ', $scope);
      $scopes = $this->entityManager()->getStorage('oauth2_server_scope')->loadByProperties([
        'server_id' => $client->getServer()->id(),
        'scope_id' => $scope_names
      ]);

      // Show the authorize form.
      return $this->formBuilder()->getForm('Drupal\oauth2_server\Form\AuthorizeForm', ['client' => $client, 'scopes' => $scopes]);
    }
  }

  public function token(RouteMatchInterface $route_match, Request $request) {
    $bridgeRequest = BridgeRequest::createFromRequest($request);

    $client_credentials = Utility::getClientCredentials($bridgeRequest);
    // Get the client and use it to load the server and initialize the server.
    $client = FALSE;
    if ($client_credentials) {
      $clients = $this->entityManager()->getStorage('oauth2_server_client')->loadByProperties(['client_id' => $client_credentials['client_id']]);
      if ($clients) {
        $client = reset($clients);
      }
    }
    if (!$client) {
      return new JsonResponse(['error' => 'Client could not be found.'], JsonResponse::HTTP_NOT_FOUND);
    }

    $response = new BridgeResponse();
    $oauth2_server = Utility::startServer($client->getServer(), $this->storage);
    $oauth2_server->handleTokenRequest($bridgeRequest, $response);
    return $response;

  }

  public function tokens(RouteMatchInterface $route_match, Request $request) {
    $token = $route_match->getRawParameter('oauth2_server_token');
    $token = $this->storage->getAccessToken($token);
    // No token found. Stop here.
    if (!$token || $token['expires'] <= time()) {
      return new BridgeResponse(array(), 404);
    }

    // Return the token, without the server and client_id keys.
    unset($token['server']);
    return new JsonResponse($token);
  }

  public function userInfo(RouteMatchInterface $route_match, Request $request) {
    $bridgeRequest = BridgeRequest::createFromRequest($request);

    $client_credentials = Utility::getClientCredentials($bridgeRequest);
    // Get the client and use it to load the server and initialize the server.
    $client = FALSE;
    if ($client_credentials) {
      $clients = $this->entityManager()->getStorage('oauth2_server_client')->loadByProperties(['client_id' => $client_credentials['client_id']]);
      if ($clients) {
        $client = reset($clients);
      }
    }

    $server = NULL;
    if ($client) {
      $server = $client->getServer();
    }

    $response = new BridgeResponse();
    $oauth2_server = Utility::startServer($server, $this->storage);
    $oauth2_server->handleUserInfoRequest($bridgeRequest, $response);
    return $response;
  }

  public function certificates(RouteMatchInterface $route_match, Request $request) {
    $keys = Utility::getKeys();
    $certificates = array();
    $certificates[] = $keys['public_key'];
    return new JsonResponse($certificates);
  }

  public function accessNeedsKeys() {

  }
}
