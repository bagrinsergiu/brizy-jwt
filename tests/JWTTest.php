<?php

namespace BrizyJWTTests;

use BrizyJWT\ExpiredException;
use BrizyJWT\JWT;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    public function testEncodeDecode()
    {
        $secret_key = 'xxx';
        $signature_key  = JWT::getSignatureKey($secret_key);
        $encryption_key = JWT::getEncryptionKey($secret_key);
        JWT::$leeway = 60;

        $payload1 = [
            'user' => 1,
            'project' => 2,
            'exp' => time()
        ];

        $token = JWT::encode($payload1, $signature_key, $encryption_key);
        $payload2 = (array)JWT::decode($token, $signature_key, $encryption_key);

        $this->assertEquals($payload1, $payload2);
    }

    public function testEncodeDecodeExpired()
    {
        $this->setExpectedException(ExpiredException::class);

        $secret_key = 'yyy';
        $signature_key  = JWT::getSignatureKey($secret_key);
        $encryption_key = JWT::getEncryptionKey($secret_key);
        JWT::$leeway = 1;

        $payload1 = [
            'user' => 1,
            'project' => 2,
            'exp' => time()
        ];

        $token = JWT::encode($payload1, $signature_key, $encryption_key);
        sleep(2);
        $payload2 = (array)JWT::decode($token, $signature_key, $encryption_key);
    }
}
