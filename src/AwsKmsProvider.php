<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * AWS KMS key provider (stub).
 *
 * This provider requires the AWS SDK for PHP. Install it with:
 *
 *     composer require aws/aws-sdk-php
 *
 * A full implementation will use KMS GenerateDataKey to produce AES-256
 * data keys for each ref.
 */
final class AwsKmsProvider implements KeyProvider
{
    public function __construct(
        string $keyId,
        string $region = 'us-east-1',
        ?string $endpointUrl = null,
    ) {
        throw new \RuntimeException(
            'AwsKmsProvider is not yet implemented. Install aws/aws-sdk-php '
            . 'and contribute an implementation, or use VaultProvider instead.'
        );
    }

    public function resolve(string $ref): KeyRecord
    {
        throw new \RuntimeException('AwsKmsProvider is not yet implemented.');
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        throw new \RuntimeException('AwsKmsProvider is not yet implemented.');
    }
}
