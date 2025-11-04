<?php

namespace Bhhaskin\RolesPermissions\Exceptions;

use RuntimeException;

class ObjectPermissionsDisabledException extends RuntimeException
{
    public static function make(): self
    {
        return new self(
            'Object level permissions are disabled. Enable them in the roles-permissions config file.'
        );
    }
}
