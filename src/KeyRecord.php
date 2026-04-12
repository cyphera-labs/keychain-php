<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

use DateTimeImmutable;

/**
 * Immutable record representing a single version of a cryptographic key.
 */
final class KeyRecord
{
    public function __construct(
        public readonly string $ref,
        public readonly int $version,
        public readonly Status $status,
        public readonly string $algorithm = 'adf1',
        public readonly string $material = '',
        public readonly ?string $tweak = null,
        /** @var array<string, string> */
        public readonly array $metadata = [],
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {}
}
