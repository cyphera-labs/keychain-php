<?php

declare(strict_types=1);

namespace Cyphera\Keychain\Tests;

use Cyphera\Keychain\KeyDisabledException;
use Cyphera\Keychain\KeyNotFoundException;
use Cyphera\Keychain\KeyRecord;
use Cyphera\Keychain\MemoryProvider;
use Cyphera\Keychain\NoActiveKeyException;
use Cyphera\Keychain\Status;
use PHPUnit\Framework\TestCase;

final class MemoryProviderTest extends TestCase
{
    private const KEY_MATERIAL = "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef";

    private static function makeRecord(
        string $ref = 'k',
        int $version = 1,
        Status $status = Status::ACTIVE,
    ): KeyRecord {
        return new KeyRecord(
            ref: $ref,
            version: $version,
            status: $status,
            material: self::KEY_MATERIAL,
        );
    }

    // ── resolve ──────────────────────────────────────────────────────

    public function testResolveActiveKey(): void
    {
        $provider = new MemoryProvider(self::makeRecord('k', 1, Status::ACTIVE));
        $record = $provider->resolve('k');

        $this->assertSame('k', $record->ref);
        $this->assertSame(1, $record->version);
        $this->assertSame(Status::ACTIVE, $record->status);
    }

    public function testResolveUnknownRefThrows(): void
    {
        $provider = new MemoryProvider();

        $this->expectException(KeyNotFoundException::class);
        $provider->resolve('missing');
    }

    public function testResolveNoActiveKeyThrows(): void
    {
        $provider = new MemoryProvider(
            self::makeRecord('k', 1, Status::DEPRECATED),
            self::makeRecord('k', 2, Status::DISABLED),
        );

        $this->expectException(NoActiveKeyException::class);
        $provider->resolve('k');
    }

    public function testResolveReturnsHighestActiveVersion(): void
    {
        $provider = new MemoryProvider(
            self::makeRecord('k', 1, Status::ACTIVE),
            self::makeRecord('k', 2, Status::ACTIVE),
            self::makeRecord('k', 3, Status::DEPRECATED),
        );

        $record = $provider->resolve('k');
        $this->assertSame(2, $record->version);
    }

    public function testResolveSkipsDeprecatedReturnsNextActive(): void
    {
        $provider = new MemoryProvider(
            self::makeRecord('k', 1, Status::ACTIVE),
            self::makeRecord('k', 2, Status::DEPRECATED),
        );

        $record = $provider->resolve('k');
        $this->assertSame(1, $record->version);
    }

    // ── resolveVersion ───────────────────────────────────────────────

    public function testResolveVersionReturnsCorrectRecord(): void
    {
        $provider = new MemoryProvider(
            self::makeRecord('k', 1, Status::ACTIVE),
            self::makeRecord('k', 2, Status::ACTIVE),
        );

        $record = $provider->resolveVersion('k', 1);
        $this->assertSame(1, $record->version);
    }

    public function testResolveVersionDisabledThrows(): void
    {
        $provider = new MemoryProvider(self::makeRecord('k', 1, Status::DISABLED));

        $this->expectException(KeyDisabledException::class);
        $provider->resolveVersion('k', 1);
    }

    public function testResolveVersionMissingRefThrows(): void
    {
        $provider = new MemoryProvider();

        $this->expectException(KeyNotFoundException::class);
        $provider->resolveVersion('missing', 1);
    }

    public function testResolveVersionMissingVersionThrows(): void
    {
        $provider = new MemoryProvider(self::makeRecord('k', 1, Status::ACTIVE));

        $this->expectException(KeyNotFoundException::class);
        $provider->resolveVersion('k', 99);
    }

    public function testResolveVersionDeprecatedAllowed(): void
    {
        $provider = new MemoryProvider(self::makeRecord('k', 1, Status::DEPRECATED));

        $record = $provider->resolveVersion('k', 1);
        $this->assertSame(1, $record->version);
        $this->assertSame(Status::DEPRECATED, $record->status);
    }

    // ── add ──────────────────────────────────────────────────────────

    public function testAddMakesKeyResolvable(): void
    {
        $provider = new MemoryProvider();
        $provider->add(self::makeRecord('k', 1, Status::ACTIVE));

        $record = $provider->resolve('k');
        $this->assertSame(1, $record->version);
    }

    public function testAddUpdatesHighestActive(): void
    {
        $provider = new MemoryProvider(self::makeRecord('k', 1, Status::ACTIVE));
        $provider->add(self::makeRecord('k', 2, Status::ACTIVE));

        $record = $provider->resolve('k');
        $this->assertSame(2, $record->version);
    }

    public function testAddMultipleRefs(): void
    {
        $provider = new MemoryProvider();
        $provider->add(self::makeRecord('alpha', 1, Status::ACTIVE));
        $provider->add(self::makeRecord('beta', 1, Status::ACTIVE));

        $this->assertSame('alpha', $provider->resolve('alpha')->ref);
        $this->assertSame('beta', $provider->resolve('beta')->ref);
    }
}
