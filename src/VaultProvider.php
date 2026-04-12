<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * Key provider backed by HashiCorp Vault KV v2 secrets engine.
 *
 * Uses file_get_contents with stream_context_create for HTTP GET requests
 * to the Vault API. No external dependencies required.
 *
 * Key records are stored at {mount}/{ref} as secret data fields.
 *
 * Single-version secret data format:
 *
 *     {
 *       "version": "1",
 *       "status": "active",
 *       "algorithm": "adf1",
 *       "material": "<hex or base64>"
 *     }
 *
 * Multi-version: store a "versions" JSON array as a field (advanced use).
 */
final class VaultProvider implements KeyProvider
{
    private string $url;
    private ?string $token;
    private string $mount;

    public function __construct(
        string $url = 'http://127.0.0.1:8200',
        ?string $token = null,
        string $mount = 'secret',
    ) {
        $this->url = rtrim($url, '/');
        $this->token = $token;
        $this->mount = $mount;
    }

    /**
     * @return array<string, mixed>
     */
    private function readData(string $ref): array
    {
        $path = "/v1/{$this->mount}/data/{$ref}";
        $fullUrl = $this->url . $path;

        $headers = ['Content-Type: application/json'];
        if ($this->token !== null) {
            $headers[] = "X-Vault-Token: {$this->token}";
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'ignore_errors' => true,
                'timeout' => 10,
            ],
        ]);

        $response = @file_get_contents($fullUrl, false, $context);
        if ($response === false) {
            throw new KeyNotFoundException($ref);
        }

        /** @var array<string, mixed> $body */
        $body = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

        if (!isset($body['data']['data']) || !is_array($body['data']['data'])) {
            throw new KeyNotFoundException($ref);
        }

        return $body['data']['data'];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function parseOne(string $ref, array $data): KeyRecord
    {
        $rawMaterial = (string) ($data['material'] ?? '');
        $material = $rawMaterial !== '' ? EnvProvider::decodeBytes($rawMaterial) : '';

        $tweakRaw = $data['tweak'] ?? null;
        $tweak = $tweakRaw !== null ? EnvProvider::decodeBytes((string) $tweakRaw) : null;

        /** @var array<string, string> $metadata */
        $metadata = $data['metadata'] ?? [];
        if (!is_array($metadata)) {
            $metadata = [];
        }

        return new KeyRecord(
            ref: (string) ($data['ref'] ?? $ref),
            version: (int) ($data['version'] ?? 1),
            status: Status::from((string) ($data['status'] ?? 'active')),
            algorithm: (string) ($data['algorithm'] ?? 'adf1'),
            material: $material,
            tweak: $tweak,
            metadata: $metadata,
        );
    }

    /**
     * @param array<string, mixed> $data
     * @return list<KeyRecord>
     */
    private function parseRecords(string $ref, array $data): array
    {
        if (isset($data['versions'])) {
            $versions = $data['versions'];
            if (is_string($versions)) {
                $versions = json_decode($versions, true, 512, JSON_THROW_ON_ERROR);
            }
            return array_map(
                fn (array $v): KeyRecord => $this->parseOne($ref, $v),
                $versions,
            );
        }
        return [$this->parseOne($ref, $data)];
    }

    public function resolve(string $ref): KeyRecord
    {
        $data = $this->readData($ref);
        $records = $this->parseRecords($ref, $data);

        $active = array_filter($records, static fn (KeyRecord $r): bool => $r->status === Status::ACTIVE);
        if ($active === []) {
            throw new NoActiveKeyException($ref);
        }

        usort($active, static fn (KeyRecord $a, KeyRecord $b): int => $b->version <=> $a->version);
        return $active[0];
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        $data = $this->readData($ref);
        $records = $this->parseRecords($ref, $data);

        foreach ($records as $record) {
            if ($record->version === $version) {
                if ($record->status === Status::DISABLED) {
                    throw new KeyDisabledException($ref, $version);
                }
                return $record;
            }
        }

        throw new KeyNotFoundException($ref, $version);
    }
}
