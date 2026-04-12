<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

/**
 * In-memory key provider.
 *
 * Accepts KeyRecord instances at construction time and via add().
 * Thread-safety note: PHP is single-threaded per request, so no locking
 * is needed unlike the Python/Java implementations.
 */
final class MemoryProvider implements KeyProvider
{
    /** @var array<string, list<KeyRecord>> keyed by ref, sorted descending by version */
    private array $store = [];

    public function __construct(KeyRecord ...$records)
    {
        foreach ($records as $record) {
            $this->insert($record);
        }
    }

    private function insert(KeyRecord $record): void
    {
        $this->store[$record->ref][] = $record;
        usort(
            $this->store[$record->ref],
            static fn (KeyRecord $a, KeyRecord $b): int => $b->version <=> $a->version,
        );
    }

    public function add(KeyRecord $record): void
    {
        $this->insert($record);
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
