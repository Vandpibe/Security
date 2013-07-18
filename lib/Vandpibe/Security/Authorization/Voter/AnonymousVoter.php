<?php

/*
 * This file is part of the Vandpibe package.
 *
 * (c) Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vandpibe\Security\Authorization\Voter;

use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * @author Henrik Bjornskov <henrik@bjrnskov.dk>
 */
class AnonymousVoter implements \Symfony\Component\Security\Core\Authorization\Voter\VoterInterface
{
    /**
     * The attribute name used for configs. `role: [IS_ANONYMOUS]`
     */
    const IS_ANONYMOUS = 'IS_ANONYMOUS';

    /**
     * @var AuthenticationTrustResolverInterface
     */
    protected $resolver;

    /**
     * @param AuthenticationTrustResolverInterface $resolver
     */
    public function __construct(AuthenticationTrustResolverInterface $resolver)
    {
        $this->resolver = $resolver;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsAttribute($attribute)
    {
        return static::IS_ANONYMOUS == $attribute;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function vote(TokenInterface $token, $object, array $attributes)
    {
        if (!array_filter($attributes, array($this, 'supportsAttribute'))) {
            // None of the attributes is supported so we will abstain from voting.
            return VoterInterface::ACCESS_ABSTAIN;
        }

        if ($this->resolver->isAnonymous()) {
            return VoterInterface::ACCESS_GRANTED;
        }

        return VoterInterface::ACCESS_DENIED;
    }
}
