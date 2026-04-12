<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

class KeyDisabledException extends KeyProviderException
{
    public function __construct(
        public readonly string $ref,
        public readonly int $version,
    ) {
        parent::__construct("key is disabled: ref='{$ref}' version={$version}");
    }
}
