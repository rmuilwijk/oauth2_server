<?php
/**
 * @file
 * Includes the scope utility class.@global
 *
 * @todo this should be rewritten to use dependency injection.
 */

namespace Drupal\oauth2_server;

use OAuth2\ScopeInterface;
use Oauth2\RequestInterface;

/**
 * Provides a scope-checking utility to the library.
 */
class ScopeUtility implements ScopeInterface {
  /**
   * @var \Drupal\oauth2_server\ServerInterface
   */
  private $server;

  public function __construct($server) {
    $this->server = $server;
  }

  /**
   * Check if everything in required scope is contained in available scope.
   *
   * @param string $required_scope
   *   A space-separated string of scopes.
   *
   * @return bool
   *   TRUE if everything in required scope is contained in available scope,
   *   and FALSE if it isn't.
   *
   * @see http://tools.ietf.org/html/rfc6749#section-7
   *
   * @ingroup oauth2_section_7
   */
  function checkScope($required_scope, $available_scope) {
    $required_scope = explode(' ', trim($required_scope));
    $available_scope = explode(' ', trim($available_scope));
    return (count(array_diff($required_scope, $available_scope)) == 0);
  }

  /**
   * Check if the provided scope exists in storage.
   *
   * @param $scope
   *   A space-separated string of scopes.
   * @param $client_id
   *   The requesting client.
   *
   * @return bool
   *   TRUE if it exists, FALSE otherwise.
   */
  function scopeExists($scope, $client_id = null) {
    $scope = explode(' ', trim($scope));
    // Get all scope entities that match the provided scope.
    // Compare the difference.
    $query = \Drupal::entityQuery('oauth2_server_scope');
    $query->condition('server_id', $this->server->id());
    $query->condition('scope_id', $scope);
    $results = $query->execute();

    $scope_ids = array_keys($results);
    $loaded_scopes = \Drupal::entityManager()->getStorage('oauth2_server_scope')->loadMultiple($scope_ids);

    // Previously $query->addTag('oauth2_server_scope_access') was used but in
    // the config entities the query alter does not run. Use an alter.
    $context = ['scopes' => &$loaded_scopes, 'server' => $this->server];
    \Drupal::moduleHandler()->alter('oauth2_server_scope_access', $context);

    if ($loaded_scopes) {
      $found_scope = array();
      foreach ($loaded_scopes as $loaded_scope) {
        $found_scope[] = $loaded_scope->label();
      }

      return (count(array_diff($scope, $found_scope)) == 0);
    }

    return FALSE;
  }

  public function getScopeFromRequest(RequestInterface $request) {
    // "scope" is valid if passed in either POST or QUERY
    return $request->request('scope', $request->query('scope'));
  }

  public function getDefaultScope($client_id = NULL) {
    // Allow any hook_oauth2_server_default_scope() implementations to supply
    // the default scope. The first one to return a scope wins.
    foreach (\Drupal::moduleHandler()->getImplementations('oauth2_server_default_scope') as $module) {
      $function = $module . '_' . 'oauth2_server_default_scope';
      $args = array($this->server);
      $result = call_user_func_array($function, $args);
      if (is_array($result)) {
        sort($result);
        return implode(' ', $result);
      }
    }

    // If there's a valid default scope set in server settings, return it.
    $default_scope = $this->server->settings['default_scope'];
    if (!empty($default_scope)) {
      $loaded_scope = \Drupal::entityManager()->getStorage('oauth2_server_scope')->load($default_scope);

      if ($loaded_scope) {
        return $loaded_scope->scope_id;
      }
    }

    return FALSE;
  }
}
