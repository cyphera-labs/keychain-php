<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * Azure Key Vault key provider (stub).
 *
 * This provider requires an Azure SDK client. A full implementation will
 * use Azure Key Vault to wrap random AES-256 data keys with an RSA key.
 */
final class AzureKvProvider implements KeyProvider
{
    public function __construct(string $vaultUrl, string $keyName)
    {
        throw new \RuntimeException(
            'AzureKvProvider is not yet implemented. Contribute an implementation, '
            . 'or use VaultProvider instead.'
        );
    }

    public function resolve(string $ref): KeyRecord
    {
        throw new \RuntimeException('AzureKvProvider is not yet implemented.');
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        throw new \RuntimeException('AzureKvProvider is not yet implemented.');
    }
}
