<?php

/*
 * This file is part of the Vandpibe package.
 *
 * (c) Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vandpibe\Test\Security\Authorization\Voter;

use Vandpibe\Security\Authorization\Voter\AnonymousVoter;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * @author Henrik Bjornskov <henrik@bjrnskov.dk>
 */
class AnonymousVoterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->resolver = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface');
        $this->token = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        $this->voter = new AnonymousVoter($this->resolver);
    }

    public function testSupportsClass()
    {
        $this->assertTrue($this->voter->supportsClass('stdClass'));
    }

    public function testSupportsAttribute()
    {
        $this->assertFalse($this->voter->supportsAttribute('ROLE_USER'));
        $this->assertFalse($this->voter->supportsAttribute('IS_AUTHENTICATION_ANONYMOUSLY'));
        $this->assertTrue($this->voter->supportsAttribute(AnonymousVoter::IS_ANONYMOUS));
    }

    public function testVoteWhenAttributeIsMissing()
    {
        $this->resolver
            ->expects($this->never())
            ->method('isAnonymous')
        ;

        $this->assertEquals(VoterInterface::ACCESS_ABSTAIN, $this->voter->vote($this->token, new \stdClass, array('ROLE_USER')));
    }

    public function testVoteWhenNotAnonymous()
    {
        $this->resolver
            ->expects($this->once())
            ->method('isAnonymous')
            ->will($this->returnValue(false))
        ;

        $this->assertEquals(VoterInterface::ACCESS_DENIED, $this->voter->vote($this->token, new \stdClass, array(AnonymousVoter::IS_ANONYMOUS)));
    }

    public function testVoteWhenAnonymous()
    {
        $this->resolver
            ->expects($this->once())
            ->method('isAnonymous')
            ->will($this->returnValue(true))
        ;

        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $this->voter->vote($this->token, new \stdClass, array(AnonymousVoter::IS_ANONYMOUS)));
    }
}
