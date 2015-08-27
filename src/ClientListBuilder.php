<?php

/**
 * @file
 * Contains \Drupal\oauth2_server\ClientListBuilder.
 */

namespace Drupal\oauth2_server;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\Entity\ConfigEntityInterface;
use Drupal\Core\Config\Entity\ConfigEntityListBuilder;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\oauth2_server\ServerInterface;
use Drupal\oauth2_server\ClientInterface;

/**
 * Builds a listing of oauth2 server client entities.
 */
class ClientListBuilder extends ConfigEntityListBuilder {
  /**
   * {@inheritdoc}
   */
  public function getDefaultOperations(EntityInterface $entity) {
    $operations = parent::getDefaultOperations($entity);

    if ($entity instanceof ClientInterface) {
      $route_parameters['oauth2_server'] = $entity->getServer()->id();
      $route_parameters['oauth2_server_client'] = $entity->id();

      $operations['edit'] = array(
        'title' => $this->t('Edit'),
        'weight' => 20,
        'url' => new Url('entity.oauth2_server.clients.edit_form', $route_parameters),
      );
      $operations['delete'] = array(
        'title' => $this->t('Delete'),
        'weight' => 30,
        'url' => new Url('entity.oauth2_server.clients.delete_form', $route_parameters),
      );
    }

    return $operations;
  }

  /**
   * {@inheritdoc}
   */
  public function buildHeader() {
    return array(
      'label' => $this->t('Label'),
    ) + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    /** @var \Drupal\Core\Config\Entity\ConfigEntityInterface $entity */
    $row = parent::buildRow($entity);

    return array(
      'data' => array(
        'label' => array(
          'data' => $this->getLabel($entity),
          'class' => array('oauth2-server-client-name'),
        ),
        'operations' => $row['operations'],
      ),
      'title' => $this->t('ID: @name', array('@name' => $entity->id())),
      'class' => array(
        Html::cleanCssIdentifier($entity->getEntityTypeId() . '-' . $entity->id())
      ),
    );
  }

  /**
   * {@inheritdoc}
   *
   * @param \Drupal\oauth2_server\ServerInterface $oauth2_server
   *   The server of which the clients should be limited to.
   *
   * @return array
   *   The client list as a renderable array.
   */
  public function render(ServerInterface $oauth2_server = NULL) {
    $build = array();
    $build['table'] = array(
      '#type' => 'table',
      '#header' => $this->buildHeader(),
      '#title' => $this->getTitle(),
      '#rows' => array(),
      '#cache' => [
        'contexts' => $this->entityType->getListCacheContexts(),
      ],
      '#attributes' => [
        'id' => 'oauth2-server-client-entity-list',
      ],
    );

    $build['table']['#empty'] = $this->t('No clients available. <a href="@link">Add client</a>.', [
      '@link' => Url::fromRoute('entity.oauth2_server.clients.add_form', ['oauth2_server' => $oauth2_server->id()])->toString()
    ]);

    if ($oauth2_server) {
      $clients = $this->storage->loadByProperties(['server_id' => $oauth2_server->id()]);
    }
    else {
      $clients = $this->storage->loadMultiple();
    }

    $this->sortAlphabetically($clients);
    foreach ($clients as $entity) {
      if ($row = $this->buildRow($entity)) {
        $build['table']['#rows'][$entity->id()] = $row;
      }
    }

    $build['pager'] = array(
      '#type' => 'pager',
    );

    return $build;
  }

  /**
   * Sorts an array of entities alphabetically.
   *
   * Will preserve the key/value association of the array.
   *
   * @param \Drupal\Core\Config\Entity\ConfigEntityInterface[] $entities
   *   An array of config entities.
   */
  protected function sortAlphabetically(array &$entities) {
    uasort($entities, function (ConfigEntityInterface $a, ConfigEntityInterface $b) {
      return strnatcasecmp($a->label(), $b->label());
    });
  }
}
