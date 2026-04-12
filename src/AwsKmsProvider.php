<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * AWS KMS key provider.
 *
 * Uses the AWS SDK for PHP to call KMS GenerateDataKey, producing AES-256
 * data keys for each ref. The plaintext data key is returned as key material
 * and the encrypted (ciphertext) copy is stored in metadata for envelope
 * encryption workflows.
 *
 * Install the AWS SDK:
 *
 *     composer require aws/aws-sdk-php
 *
 * Supports an optional endpoint URL override for LocalStack or other
 * KMS-compatible services.
 */
final class AwsKmsProvider implements KeyProvider
{
    private string $keyId;
    private string $region;
    private ?string $endpointUrl;

    /** @var \Aws\Kms\KmsClient|null */
    private ?object $client = null;

    /** @var array<string, KeyRecord> */
    private array $cache = [];

    public function __construct(
        string $keyId,
        string $region = 'us-east-1',
        ?string $endpointUrl = null,
    ) {
        if (!class_exists(\Aws\Kms\KmsClient::class)) {
            throw new KeyProviderException(
                'The aws/aws-sdk-php package is required for AwsKmsProvider. '
                . 'Install it with: composer require aws/aws-sdk-php'
            );
        }

        $this->keyId = $keyId;
        $this->region = $region;
        $this->endpointUrl = $endpointUrl;
    }

    public function resolve(string $ref): KeyRecord
    {
        if (isset($this->cache[$ref])) {
            return $this->cache[$ref];
        }

        $client = $this->getClient();

        try {
            /** @var \Aws\Result $result */
            $result = $client->generateDataKey([
                'KeyId' => $this->keyId,
                'KeySpec' => 'AES_256',
            ]);
        } catch (\Aws\Exception\AwsException $e) {
            throw new KeyProviderException(
                "AWS KMS GenerateDataKey failed for ref={$ref}: {$e->getMessage()}",
                (int) $e->getCode(),
                $e,
            );
        }

        $plaintext = (string) $result['Plaintext'];
        $ciphertextBlob = base64_encode((string) $result['CiphertextBlob']);

        $record = new KeyRecord(
            ref: $ref,
            version: 1,
            status: Status::ACTIVE,
            algorithm: 'adf1',
            material: $plaintext,
            metadata: [
                'ciphertext_blob' => $ciphertextBlob,
                'key_id' => (string) $result['KeyId'],
            ],
        );

        $this->cache[$ref] = $record;

        return $record;
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        $record = $this->resolve($ref);

        if ($record->version !== $version) {
            throw new KeyNotFoundException($ref, $version);
        }

        return $record;
    }

    private function getClient(): object
    {
        if ($this->client !== null) {
            return $this->client;
        }

        $config = [
            'version' => 'latest',
            'region' => $this->region,
        ];

        if ($this->endpointUrl !== null) {
            $config['endpoint'] = $this->endpointUrl;
        }

        $this->client = new \Aws\Kms\KmsClient($config);

        return $this->client;
    }
}
