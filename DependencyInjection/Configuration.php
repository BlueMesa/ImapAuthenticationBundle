<?php

namespace Bluemesa\Bundle\ImapAuthenticationBundle\DependencyInjection;

use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Configuration implements ConfigurationInterface
{
  public function getConfigTreeBuilder()
  {
    $treeBuilder = new TreeBuilder();
    $rootNode = $treeBuilder->root('bluemesa_imap_authentication');
    $rootNode
        ->children()
            ->append($this->addConnectionsNode())
            ->scalarNode('user_class')
              ->defaultValue('Bluemesa\\ImapAuthenticationBundle\\User\\ImapUser')
            ->end()
        ->end()
        ;

    return $treeBuilder;
  }

  private function addConnectionsNode()
  {
      $treeBuilder = new TreeBuilder();
      $node = $treeBuilder->root('connections');

      $node
          ->prototype('array')
          ->children()
              ->scalarNode('host')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('port')->defaultValue(143)->end()
              ->booleanNode('secure')->defaultTrue()->end()
              ->booleanNode('email_login')->defaultFalse()->end()
              ->enumNode('encryption')->values(array('none', 'ssl', 'tls'))->end()
              ->booleanNode('validate_cert')->defaultTrue()->end()
              ->integerNode('n_retries')->defaultValue(0)->end()
              ->arrayNode('domains')->prototype('scalar')->end()
           ->end()
          ;

      return $node;
  }
}
