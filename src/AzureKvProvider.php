<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * Azure Key Vault key provider.
 *
 * Uses the Azure Key Vault REST API directly via file_get_contents
 * (no external SDK required). Generates a random AES-256 data key locally
 * and wraps it with an RSA key stored in Azure Key Vault using the
 * WrapKey operation (RSA-OAEP algorithm).
 *
 * Authentication uses an OAuth2 bearer token which can be supplied
 * directly or obtained from the Azure Instance Metadata Service (IMDS)
 * for managed identities.
 *
 * @see https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key
 */
final class AzureKvProvider implements KeyProvider
{
    private string $vaultUrl;
    private string $keyName;
    private ?string $keyVersion;
    private ?string $accessToken;

    /** @var array<string, KeyRecord> */
    private array $cache = [];

    public function __construct(
        string $vaultUrl,
        string $keyName,
        ?string $keyVersion = null,
        ?string $accessToken = null,
    ) {
        $this->vaultUrl = rtrim($vaultUrl, '/');
        $this->keyName = $keyName;
        $this->keyVersion = $keyVersion;
        $this->accessToken = $accessToken;
    }

    public function resolve(string $ref): KeyRecord
    {
        if (isset($this->cache[$ref])) {
            return $this->cache[$ref];
        }

        $plaintext = random_bytes(32);

        $token = $this->getAccessToken();
        $wrappedKey = $this->wrapKey($plaintext, $token);

        $record = new KeyRecord(
            ref: $ref,
            version: 1,
            status: Status::ACTIVE,
            algorithm: 'adf1',
            material: $plaintext,
            metadata: [
                'wrapped_key' => $wrappedKey,
                'vault_url' => $this->vaultUrl,
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

    /**
     * Wrap a plaintext key using the Azure Key Vault WrapKey REST API.
     */
    private function wrapKey(string $plaintext, string $token): string
    {
        $keyPath = $this->keyVersion !== null
            ? "/keys/{$this->keyName}/{$this->keyVersion}"
            : "/keys/{$this->keyName}";

        $url = $this->vaultUrl . $keyPath . '/wrapkey?api-version=7.4';

        $payload = json_encode([
            'alg' => 'RSA-OAEP',
            'value' => rtrim(strtr(base64_encode($plaintext), '+/', '-_'), '='),
        ], JSON_THROW_ON_ERROR);

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", [
                    'Content-Type: application/json',
                    "Authorization: Bearer {$token}",
                ]),
                'content' => $payload,
                'ignore_errors' => true,
                'timeout' => 10,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            throw new KeyProviderException(
                "Azure Key Vault WrapKey request failed for key={$this->keyName}",
            );
        }

        /** @var array<string, mixed> $body */
        $body = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

        if (isset($body['error'])) {
            $message = $body['error']['message'] ?? 'unknown error';
            throw new KeyProviderException(
                "Azure Key Vault WrapKey failed: {$message}",
            );
        }

        if (!isset($body['value'])) {
            throw new KeyProviderException(
                'Azure Key Vault WrapKey response missing "value" field.',
            );
        }

        return (string) $body['value'];
    }

    /**
     * Return the bearer token for Azure Key Vault API calls.
     *
     * If a token was provided at construction time, return it directly.
     * Otherwise attempt to obtain one from the Azure Instance Metadata
     * Service (IMDS) for managed identities.
     */
    private function getAccessToken(): string
    {
        if ($this->accessToken !== null) {
            return $this->accessToken;
        }

        $url = 'http://169.254.169.254/metadata/identity/oauth2/token'
            . '?api-version=2019-08-01'
            . '&resource=https%3A%2F%2Fvault.azure.net';

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => 'Metadata: true',
                'ignore_errors' => true,
                'timeout' => 5,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            throw new KeyProviderException(
                'Failed to obtain Azure access token from IMDS. '
                . 'Provide an access token explicitly or ensure managed identity is configured.',
            );
        }

        /** @var array<string, mixed> $body */
        $body = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

        if (!isset($body['access_token'])) {
            throw new KeyProviderException(
                'Azure IMDS response did not contain an access_token.',
            );
        }

        $this->accessToken = (string) $body['access_token'];

        return $this->accessToken;
    }
}
