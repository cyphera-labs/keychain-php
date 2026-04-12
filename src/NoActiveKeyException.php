<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

class NoActiveKeyException extends KeyProviderException
{
    public function __construct(
        public readonly string $ref,
    ) {
        parent::__construct("no active key found: ref='{$ref}'");
    }
}
