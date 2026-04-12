<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * Key provider interface.
 *
 * Implementations supply cryptographic key material from various backends
 * (memory, environment variables, files, Vault, cloud KMS, etc.).
 */
interface KeyProvider
{
    /**
     * Return the highest-version active record for encryption.
     *
     * @throws KeyNotFoundException
     * @throws NoActiveKeyException
     */
    public function resolve(string $ref): KeyRecord;

    /**
     * Return a specific version of a key record for decryption.
     *
     * @throws KeyNotFoundException
     * @throws KeyDisabledException
     */
    public function resolveVersion(string $ref, int $version): KeyRecord;
}
