<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

use DateTimeImmutable;

/**
 * Key provider that loads keys from a local JSON file.
 *
 * Expected file structure:
 *
 *     {
 *         "keys": [
 *             {
 *                 "ref": "customer-primary",
 *                 "version": 1,
 *                 "status": "active",
 *                 "algorithm": "adf1",
 *                 "material": "<hex or base64>",
 *                 "tweak": "<hex or base64>",
 *                 "metadata": {},
 *                 "created_at": "2024-01-01T00:00:00"
 *             }
 *         ]
 *     }
 *
 * The file is read once at construction time.
 */
final class FileProvider implements KeyProvider
{
    /** @var array<string, list<KeyRecord>> keyed by ref, sorted descending by version */
    private array $store = [];

    public function __construct(string $path)
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException("Cannot read key file: {$path}");
        }

        /** @var array{keys?: list<array<string, mixed>>} $data */
        $data = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);

        foreach ($data['keys'] ?? [] as $obj) {
            $record = self::parseRecord($obj);
            $this->store[$record->ref][] = $record;
        }

        foreach ($this->store as &$versions) {
            usort($versions, static fn (KeyRecord $a, KeyRecord $b): int => $b->version <=> $a->version);
        }
    }

    /**
     * @param array<string, mixed> $obj
     */
    private static function parseRecord(array $obj): KeyRecord
    {
        $ref = (string) $obj['ref'];
        $version = (int) $obj['version'];
        $status = Status::from((string) $obj['status']);
        $algorithm = (string) ($obj['algorithm'] ?? 'adf1');
        $material = EnvProvider::decodeBytes((string) $obj['material']);

        $tweak = null;
        if (!empty($obj['tweak'])) {
            $tweak = EnvProvider::decodeBytes((string) $obj['tweak']);
        }

        /** @var array<string, string> $metadata */
        $metadata = $obj['metadata'] ?? [];

        $createdAt = null;
        if (!empty($obj['created_at'])) {
            $createdAt = new DateTimeImmutable((string) $obj['created_at']);
        }

        return new KeyRecord(
            ref: $ref,
            version: $version,
            status: $status,
            algorithm: $algorithm,
            material: $material,
            tweak: $tweak,
            metadata: $metadata,
            createdAt: $createdAt,
        );
    }

    public function resolve(string $ref): KeyRecord
    {
        $versions = $this->store[$ref] ?? [];
        if ($versions === []) {
            throw new KeyNotFoundException($ref);
        }

        foreach ($versions as $record) {
            if ($record->status === Status::ACTIVE) {
                return $record;
            }
        }

        throw new NoActiveKeyException($ref);
    }

    public function resolveVersion(string $ref, int $version): KeyRecord
    {
        $versions = $this->store[$ref] ?? [];
        if ($versions === []) {
            throw new KeyNotFoundException($ref, $version);
        }

        foreach ($versions as $record) {
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
