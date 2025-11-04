<?php

namespace Bhhaskin\RolesPermissions\Exceptions;

use InvalidArgumentException;

class RoleScopeMismatchException extends InvalidArgumentException
{
    public static function make(string $roleScope, ?string $contextScope): self
    {
        $message = sprintf(
            'Role scope "%s" does not match the provided context scope "%s".',
            $roleScope,
            $contextScope ?? 'null'
        );

        return new self($message);
    }
}
