<?php

namespace BrizyJWT;

use \DomainException;
use \InvalidArgumentException;
use \UnexpectedValueException;
use \DateTime;

class JWT
{
    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static $leeway = 0;

    public static $alg = 'SHA256';

    public static $enc_alg = 'AES-128-CBC';

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string            $jwt            The JWT
     * @param $signature_key
     * @param $encryption_key
     *
     * @return object The JWT's payload as a PHP object
     *
     * @throws DomainException              Algorithm was not provided
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode($jwt, $signature_key, $encryption_key)
    {
        if (empty($signature_key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }

        $tks = explode('.', $jwt);
        if (count($tks) != 2) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($bodyb64, $cryptob64) = $tks;

        if (null === $payload = JWT::jsonDecode(JWT::decrypt(JWT::urlsafeB64Decode($bodyb64), $encryption_key))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        $sig = JWT::urlsafeB64Decode($cryptob64);

        // Check the signature
        if (!JWT::verify("$bodyb64", $sig, $signature_key, self::$alg)) {
            throw new SignatureInvalidException('Signature verification failed');
        }

//        // Check if the nbf if it is defined. This is the time that the
//        // token can actually be used. If it's not yet that time, abort.
//        if (isset($payload->nbf) && $payload->nbf > (time() + self::$leeway)) {
//            throw new BeforeValidException(
//                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf)
//            );
//        }
//
//        // Check that this token has been created before 'now'. This prevents
//        // using tokens that have been created for later use (and haven't
//        // correctly used the nbf claim).
//        if (isset($payload->iat) && $payload->iat > (time() + self::$leeway)) {
//            throw new BeforeValidException(
//                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat)
//            );
//        }
//
        // Check if this token has expired.
        if (isset($payload->exp) && (time() - self::$leeway) >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }

        return $payload;
    }

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array  $payload    PHP object or array
     * @param $signature_key
     * @param $encryption_key
     *
     * @return string A signed JWT
     *
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public static function encode($payload, $signature_key, $encryption_key)
    {
        $segments = array();

        $segments[] = JWT::urlsafeB64Encode(JWT::encrypt(JWT::jsonEncode($payload), $encryption_key));
        $signing_input = implode('.', $segments);

        $signature = JWT::sign($signing_input, $signature_key, self::$alg);
        $segments[] = JWT::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string            $msg    The message to sign
     * @param string|resource   $key    The secret key
     * @param string            $alg    The signing algorithm.
     *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     *
     * @return string An encrypted message
     *
     * @throws DomainException Unsupported algorithm was specified
     */
    public static function sign($msg, $key, $alg = 'HS256')
    {
        return hash_hmac($alg, $msg, $key, true);
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string            $msg        The original message (header and body)
     * @param string            $signature  The original signature
     * @param string|resource   $key        For HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string            $alg        The algorithm
     *
     * @return bool
     *
     * @throws DomainException Invalid Algorithm or OpenSSL failure
     */
    private static function verify($msg, $signature, $key, $alg)
    {
        $hash = hash_hmac($alg, $msg, $key, true);
        if (function_exists('hash_equals')) {
            return hash_equals($signature, $hash);
        }
        $len = min(self::safeStrlen($signature), self::safeStrlen($hash));

        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($signature[$i]) ^ ord($hash[$i]));
        }
        $status |= (self::safeStrlen($signature) ^ self::safeStrlen($hash));

        return ($status === 0);
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     *
     * @throws DomainException Provided string was invalid JSON
     */
    public static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            /** Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             *them to strings) before decoding, hence the preg_replace() call.
             */
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input A PHP object or array
     *
     * @return string JSON representation of the PHP object or array
     *
     * @throws DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        return $json;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new DomainException(
            isset($messages[$errno])
                ? $messages[$errno]
                : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string
     *
     * @return int
     */
    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }


    public static function encrypt($json_payload, $encryption_key)
    {
        return openssl_encrypt($json_payload, self::$enc_alg , $encryption_key, OPENSSL_RAW_DATA, self::getInitVector($encryption_key));
    }

    public static function decrypt($json_payload, $encryption_key)
    {
        return openssl_decrypt($json_payload, self::$enc_alg , $encryption_key, OPENSSL_RAW_DATA, self::getInitVector($encryption_key));
    }


    public static function getSignatureKey($secret_key)
    {
        $key_material = hash(self::$alg, $secret_key, true);

        return substr($key_material, 16, 16);
    }

    public static function getEncryptionKey($secret_key)
    {
        $key_material = hash(self::$alg, $secret_key, true);

        return substr($key_material, 0, 16);
    }

    public static function getInitVector($encryption_key)
    {
        $key_material = hash(self::$alg, $encryption_key, true);

        return substr($key_material, 0, 16);
    }

}
