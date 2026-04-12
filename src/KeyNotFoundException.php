<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

class KeyNotFoundException extends KeyProviderException
{
    public function __construct(
        public readonly string $ref,
        public readonly ?int $version = null,
    ) {
        $msg = $version !== null
            ? "key not found: ref='{$ref}' version={$version}"
            : "key not found: ref='{$ref}'";
        parent::__construct($msg);
    }
}
