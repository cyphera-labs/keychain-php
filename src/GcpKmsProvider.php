<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * GCP Cloud KMS key provider (stub).
 *
 * This provider requires the Google Cloud KMS client. Install it with:
 *
 *     composer require google/cloud-kms
 *
 * A full implementation will use Cloud KMS encrypt to wrap random AES-256
 * data keys for each ref.
 */
final class GcpKmsProvider implements KeyProvider
{
    public function __construct(string $keyName)
    {
        throw new \RuntimeException(
            'GcpKmsProvider is not yet implemented. Install google/cloud-kms '
            . 'and contribute an implementation, or use VaultProvider instead.'
        );
    }

    public function resolve(string $ref): KeyRecord
    {
        throw new \RuntimeException('GcpKmsProvider is not yet implemented.');
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        throw new \RuntimeException('GcpKmsProvider is not yet implemented.');
    }
}
