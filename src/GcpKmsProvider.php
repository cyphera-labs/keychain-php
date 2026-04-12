<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * GCP Cloud KMS key provider.
 *
 * Uses the Google Cloud KMS client to wrap locally-generated AES-256 data
 * keys. The plaintext is returned as key material and the KMS-encrypted
 * ciphertext is stored in metadata for envelope encryption workflows.
 *
 * Install the Google Cloud KMS client:
 *
 *     composer require google/cloud-kms
 *
 * The $keyName must be the full CryptoKey resource name:
 *
 *     projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}
 */
final class GcpKmsProvider implements KeyProvider
{
    private string $keyName;

    /** @var \Google\Cloud\Kms\V1\Client\KeyManagementServiceClient|null */
    private ?object $client = null;

    /** @var array<string, KeyRecord> */
    private array $cache = [];

    public function __construct(string $keyName)
    {
        if (!class_exists(\Google\Cloud\Kms\V1\Client\KeyManagementServiceClient::class)) {
            throw new KeyProviderException(
                'The google/cloud-kms package is required for GcpKmsProvider. '
                . 'Install it with: composer require google/cloud-kms'
            );
        }

        $this->keyName = $keyName;
    }

    public function resolve(string $ref): KeyRecord
    {
        if (isset($this->cache[$ref])) {
            return $this->cache[$ref];
        }

        $plaintext = random_bytes(32);

        $client = $this->getClient();

        try {
            $request = new \Google\Cloud\Kms\V1\EncryptRequest();
            $request->setName($this->keyName);
            $request->setPlaintext($plaintext);

            /** @var \Google\Cloud\Kms\V1\EncryptResponse $response */
            $response = $client->encrypt($request);
        } catch (\Google\ApiCore\ApiException $e) {
            throw new KeyProviderException(
                "GCP KMS Encrypt failed for ref={$ref}: {$e->getMessage()}",
                (int) $e->getCode(),
                $e,
            );
        }

        $ciphertext = base64_encode($response->getCiphertext());

        $record = new KeyRecord(
            ref: $ref,
            version: 1,
            status: Status::ACTIVE,
            algorithm: 'adf1',
            material: $plaintext,
            metadata: [
                'ciphertext' => $ciphertext,
                'key_name' => $this->keyName,
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

        $this->client = new \Google\Cloud\Kms\V1\Client\KeyManagementServiceClient();

        return $this->client;
    }
}
