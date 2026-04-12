<?php

declare(strict_types=1);

namespace Cyphera\Keychain;

enum Status: string
{
    case ACTIVE = 'active';
    case DEPRECATED = 'deprecated';
    case DISABLED = 'disabled';
}
