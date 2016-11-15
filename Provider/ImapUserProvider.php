<?php

/*
 * This file is part of the ImapAuthenticationBundle.
 * 
 * Copyright (c) 2016 BlueMesa LabDB Contributors <labdb@bluemesa.eu>
 * 
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Bluemesa\Bundle\ImapAuthenticationBundle\Provider;

use Egulias\EmailValidator\EmailParser;
use Egulias\EmailValidator\EmailLexer;
use FOS\UserBundle\Security\UserProvider as BaseUserProvider;
use FOS\UserBundle\Model\UserManagerInterface;
use FOS\UserBundle\Model\UserInterface;
use JMS\DiExtraBundle\Annotation as DI;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;


/**
 * Generic IMAP UserProvider
 *
 * @author Radoslaw Kamil Ejsmont <radoslaw@ejsmont.net>
 */
abstract class ImapUserProvider extends BaseUserProvider implements ImapUserProviderInterface
{
    const DOMAIN = 'undefined';

    /**
     * @var EmailParser
     */
    protected $emailParser;
    
    /**
     * @DI\InjectParams({
     *     "userManager" = @DI\Inject("fos_user.user_manager")
     * })
     * 
     * {@inheritDoc}
     */
    public function __construct(UserManagerInterface $userManager)
    {
        parent::__construct($userManager);
        $this->emailParser = new EmailParser(new EmailLexer());
    }

    /**
     * {@inheritDoc}
     */
    public function loadUserByUsername($username)
    {
        $parts = $this->splitUsername($username);
        $this->verifyDomain($parts['domain']);        
        $user = parent::loadUserByUsername($username);
        
        return $user;
    }
    
    /**
     * Create a new user using imap data source
     *
     * @param  TokenInterface $token
     * @return UserInterface
     */
    public function createUser(TokenInterface $token)
    {
        $user = $this->userManager->createUser();
        $user->setUsername($token->getUsername());
        $this->setUserData($user);

        return $user;
    }

    /**
     * Update user using imap data source
     *
     * @param  TokenInterface  $token
     * @return UserInterface
     */
    public function updateUser(TokenInterface $token)
    {
        $user = $this->loadUserByUsername($token->getUsername());
        $this->setUserData($user);

        return $user;
    }

    /**
     * Set user data using imap data source
     *
     * @param UserInterface  $user
     */
    protected abstract function setUserData(UserInterface $user);

    /**
     * @param  int     $length
     * @return string
     */
    protected function generateRandomString($length = 10) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }

        return $randomString;
    }

    /**
     * @param  string $domain
     * @throws \Exception
     * @throws UsernameNotFoundException
     */
    protected function verifyDomain($domain)
    {
        if (static::DOMAIN == 'undefined') {
            throw new \Exception('Constant DOMAIN is not defined on subclass ' . get_class($this));
        } elseif ($domain != static::DOMAIN) {
            throw new UsernameNotFoundException();
        }
    }

    /**
     * @param string $username
     * @return array
     */
    protected function splitUsername($username)
    {
        try {
            $parts = $this->emailParser->parse($username);
        } catch (\Exception $e) {
            throw new UsernameNotFoundException();
        }

        return $parts;
    }
}
