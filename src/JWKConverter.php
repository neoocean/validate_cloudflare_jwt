<?php

/*
 * This file is part of the JwkFromOidcToken package.
 *
 * (c) codercat <1067302838@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace CoderCat\JWKToPEM;

// use phpseclib\Crypt\RSA;
use Crypt_RSA;

include_once $absolute_path . 'src/phpseclib1.0.18/Math/BigInteger.php';
use Math_BigInteger;



use CoderCat\JWKToPEM\Util\Base64UrlDecoder;
use CoderCat\JWKToPEM\Exception\JWKConverterException;



class JWKConverter
{

    /** @var Base64UrlDecoder */
    private $base64UrlDecoder;

    public function __construct(Base64UrlDecoder $base64UrlDecoder = null)
    {
        $this->base64UrlDecoder = $base64UrlDecoder ?? new Base64UrlDecoder();
    }

    /**
     * @param array $jwk
     * @return string
     * @throws Exception\Base64DecodeException
     * @throws JWKConverterException
     */
    public function toPEM(array $jwk): string
    {
        if (!array_key_exists('e', $jwk) || !array_key_exists('n', $jwk) || !array_key_exists('kty', $jwk)) {
            throw new JWKConverterException();
        }

        if ($jwk['kty'] != 'RSA') {
            throw new JWKConverterException('RSA key type is currently only supported.');
        }

        if (array_key_exists('d', $jwk)) {
            throw new JWKConverterException('Public key is currently only supported.');
        }

        $rsa = new Crypt_RSA();
        $rsa->loadKey(
            [
                'e' => new Math_BigInteger(base64_decode($jwk['e']), 256),
                'n' => new Math_BigInteger($this->base64UrlDecoder->decode($jwk['n']), 256)
            ]
        );
   
        return $rsa->getPublicKey();
    }

}