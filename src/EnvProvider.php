<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * Key provider that reads keys from environment variables.
 *
 * For a ref of "customer-primary" and prefix "CYPHERA", the provider looks
 * for CYPHERA_CUSTOMER_PRIMARY_KEY (hex or base64 encoded) and optionally
 * CYPHERA_CUSTOMER_PRIMARY_TWEAK.
 *
 * All keys provided via environment variables are version 1 and status active.
 */
final class EnvProvider implements KeyProvider
{
    private string $prefix;

    public function __construct(string $prefix = 'CYPHERA')
    {
        $this->prefix = rtrim($prefix, '_');
    }

    private function envKey(string $ref, string $suffix): string
    {
        $normalized = strtoupper(str_replace(['-', '.'], '_', $ref));
        return "{$this->prefix}_{$normalized}_{$suffix}";
    }

    private function load(string $ref): KeyRecord
    {
        $keyVar = $this->envKey($ref, 'KEY');
        $raw = getenv($keyVar);
        if ($raw === false) {
            throw new KeyNotFoundException($ref);
        }

        $material = self::decodeBytes($raw);

        $tweak = null;
        $tweakVar = $this->envKey($ref, 'TWEAK');
        $rawTweak = getenv($tweakVar);
        if ($rawTweak !== false) {
            $tweak = self::decodeBytes($rawTweak);
        }

        return new KeyRecord(
            ref: $ref,
            version: 1,
            status: Status::ACTIVE,
            material: $material,
            tweak: $tweak,
        );
    }

    public function resolve(string $ref): KeyRecord
    {
        return $this->load($ref);
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        if ($version !== 1) {
            throw new KeyNotFoundException($ref, $version);
        }
        return $this->load($ref);
    }

    /**
     * Try hex decoding first, then standard base64, then URL-safe base64.
     */
    public static function decodeBytes(string $value): string
    {
        // Attempt hex
        if (ctype_xdigit($value) && strlen($value) % 2 === 0) {
            $decoded = hex2bin($value);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        // Attempt standard base64
        $decoded = base64_decode($value, true);
        if ($decoded !== false) {
            return $decoded;
        }

        // Attempt URL-safe base64
        $urlSafe = strtr($value, '-_', '+/');
        $padded = str_pad($urlSafe, (int) (ceil(strlen($urlSafe) / 4) * 4), '=');
        $decoded = base64_decode($padded, true);
        if ($decoded !== false) {
            return $decoded;
        }

        throw new \InvalidArgumentException("Cannot decode value as hex or base64: '{$value}'");
    }
}
