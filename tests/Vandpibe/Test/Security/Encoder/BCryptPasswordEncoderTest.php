<?php

/*
 * This file is part of the Vandpibe package.
 *
 * (c) Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vandpibe\Test\Security\Encoder;

use Vandpibe\Security\Encoder\BCryptPasswordEncoder;

/**
 * @author Henrik Bjornskov <henrik@bjrnskov.dk>
 */
class BCryptPasswordEncoderTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->encoder = new BCryptPasswordEncoder();
    }

    public function testEncodePassword()
    {
        $regExp = '/^' . preg_quote('$2a$05$') . '.+$/';

        $this->assertRegExp($regExp, $this->encoder->encodePassword('password', null));
    }

    public function testIsPasswordValid()
    {
        $encodedPassword = $this->encoder->encodePassword('password', null);

        $this->assertTrue($this->encoder->isPasswordValid($encodedPassword, 'password', null));
    }
}
