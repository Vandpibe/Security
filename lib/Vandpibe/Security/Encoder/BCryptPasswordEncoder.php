<?php

/*
 * This file is part of the Vandpibe package.
 *
 * (c) Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vandpibe\Security\Encoder;

/**
 * Blowfish Crypt (BCrypt) PasswordEncoder.
 * For information about why bcrypt should be use see this article:
 *
 *     Use BCrypt Fool! http://yorickpeterse.com/articles/use-bcrypt-fool
 *
 * Note: The salt parameter in ``encoderPassword`` and ``isPasswordValid`` is ignore as the salt
 * is embedded within the hashed password.
 *
 * @author Henrik Bjornskov <henrik@bjrnskov.dk>
 * @author Elnur Abdurrakhimov
 */
class BCryptPasswordEncoder extends \Symfony\Component\Security\Core\Encoder\BasePasswordEncoder
{
    /**
     * @var integer
     */
    protected $cost;

    /**
     * @param integer $cost
     */
    public function __construct($cost = 5)
    {
        // Zero pad
        $this->cost = sprintf('%02d', $cost);

        // If blowfish isn't available on the system throw and exception.
        if (CRYPT_BLOWFISH == 0) {
            throw new \LogicException('The "Blowfish" algorithm is not supported on your system.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function encodePassword($raw, $salt)
    {
        return crypt($raw, '$2a$' . $this->cost . '$' . $this->generateRandomSalt() . '$');
    }

    /**
     * {@inheritdoc}
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        return $this->comparePasswords($encoded, crypt($raw, $encoded));
    }

    /**
     * Generates a truely random salt
     *
     * @return string
     */
    public function generateRandomSalt()
    {
        $salt = null;

        if (function_exists('openssl_random_pseudo_bytes')) {
            $salt = openssl_random_pseudo_bytes(16);
        }

        if (is_null($salt)) {
            $salt = sha1(microtime(), true);
        }

        $salt = base64_encode($salt);
        $salt = strtr($salt, '+', '.');

        return substr($salt, 0, 22);
    }
}
