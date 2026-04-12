# keychain-php

Pluggable key provider for the [Cyphera](https://cyphera.dev) encryption SDK (PHP).

## Installation

```bash
composer require cyphera/cyphera-keychain
```

Requires PHP 8.1 or later.

## Providers

| Provider | Backend | Status |
|---|---|---|
| `MemoryProvider` | In-memory store | Stable |
| `EnvProvider` | Environment variables | Stable |
| `FileProvider` | Local JSON file | Stable |
| `VaultProvider` | HashiCorp Vault KV v2 | Stable |
| `AwsKmsProvider` | AWS KMS | Stub |
| `GcpKmsProvider` | GCP Cloud KMS | Stub |
| `AzureKvProvider` | Azure Key Vault | Stub |

## Quick Start

```php
use Cyphera\Keychain\MemoryProvider;
use Cyphera\Keychain\KeyRecord;
use Cyphera\Keychain\Status;

$provider = new MemoryProvider(
    new KeyRecord(ref: 'my-key', version: 1, status: Status::ACTIVE, material: $keyBytes),
);

$record = $provider->resolve('my-key');
// $record->material contains the raw key bytes
```

### Vault Provider

```php
use Cyphera\Keychain\VaultProvider;

$provider = new VaultProvider(
    url: 'http://127.0.0.1:8200',
    token: 'my-token',
    mount: 'secret',
);

$record = $provider->resolve('customer-primary');
```

### Bridge Resolver

The `Bridge` class provides a static resolver for config-driven key sources:

```php
use Cyphera\Keychain\Bridge;

$material = Bridge::resolve('vault', [
    'ref' => 'customer-primary',
    'addr' => 'http://127.0.0.1:8200',
    'token' => 'my-token',
]);
```

## Environment Variables

- `VAULT_ADDR` -- Vault server URL (used by VaultProvider and Bridge)
- `VAULT_TOKEN` -- Vault authentication token

## Development

```bash
composer install
composer test
```

### Integration Tests

```bash
docker compose up -d
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=test-token composer test
```

## License

Apache-2.0. See [LICENSE](LICENSE).
