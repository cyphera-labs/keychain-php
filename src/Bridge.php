<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * Bridge resolver for Cyphera SDK config-driven key sources.
 *
 * Called by the SDK when cyphera.json has "source" set to a cloud provider.
 * Returns raw key material bytes.
 */
final class Bridge
{
    private function __construct() {}

    /**
     * Resolve a key from a provider based on source type and config.
     *
     * @param string $source Provider type: "vault", "memory", "env", "file",
     *                       "aws-kms", "gcp-kms", "azure-kv"
     * @param array<string, mixed> $config Provider-specific configuration
     * @return string Raw key material bytes
     */
    public static function resolve(string $source, array $config): string
    {
        $ref = self::firstNonEmpty(
            $config['ref'] ?? null,
            $config['path'] ?? null,
            $config['arn'] ?? null,
            $config['key'] ?? null,
            'default',
        );

        $provider = self::createProvider($source, $config);
        $record = $provider->resolve($ref);

        return $record->material;
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function createProvider(string $source, array $config): KeyProvider
    {
        return match ($source) {
            'vault' => new VaultProvider(
                url: self::firstNonEmpty(
                    $config['addr'] ?? null,
                    getenv('VAULT_ADDR') ?: null,
                    'http://127.0.0.1:8200',
                ),
                token: self::firstNonEmpty(
                    $config['token'] ?? null,
                    getenv('VAULT_TOKEN') ?: null,
                ),
                mount: (string) ($config['mount'] ?? 'secret'),
            ),
            'aws-kms' => new AwsKmsProvider(
                keyId: (string) ($config['arn'] ?? ''),
                region: self::firstNonEmpty(
                    $config['region'] ?? null,
                    getenv('AWS_REGION') ?: null,
                    'us-east-1',
                ),
                endpointUrl: $config['endpoint'] ?? null,
            ),
            'gcp-kms' => new GcpKmsProvider(
                keyName: (string) ($config['resource'] ?? ''),
            ),
            'azure-kv' => new AzureKvProvider(
                vaultUrl: 'https://' . ($config['vault'] ?? '') . '.vault.azure.net',
                keyName: (string) ($config['key'] ?? ''),
            ),
            default => throw new \InvalidArgumentException("Unknown source: {$source}"),
        };
    }

    private static function firstNonEmpty(?string ...$values): string
    {
        foreach ($values as $v) {
            if ($v !== null && $v !== '') {
                return $v;
            }
        }
        return '';
    }
}
