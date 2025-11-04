<?php

namespace Bhhaskin\RolesPermissions\Models;

use Bhhaskin\RolesPermissions\Database\Factories\RoleFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Str;

class Role extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'slug',
        'description',
        'scope',
    ];

    protected $casts = [
        'name' => 'string',
        'slug' => 'string',
        'description' => 'string',
        'scope' => 'string',
        'uuid' => 'string',
    ];

    public function getTable(): string
    {
        return config('roles-permissions.tables.roles', parent::getTable());
    }

    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(
            $this->permissionModel(),
            config('roles-permissions.tables.permission_role', 'permission_role')
        )->withTimestamps();
    }

    public function users(): BelongsToMany
    {
        return $this->belongsToMany(
            $this->userModel(),
            config('roles-permissions.tables.role_user', 'role_user')
        )->withTimestamps();
    }

    protected static function booted(): void
    {
        static::creating(function (self $role) {
            if (! $role->uuid) {
                $role->uuid = (string) Str::uuid();
            }
        });
    }

    protected function setSlugAttribute(?string $value): void
    {
        $this->attributes['slug'] = $value ? Str::lower(trim($value)) : null;
    }

    protected function setNameAttribute(?string $value): void
    {
        $this->attributes['name'] = $value ? trim($value) : null;
    }

    protected function setDescriptionAttribute(?string $value): void
    {
        $this->attributes['description'] = $value ? trim($value) : null;
    }

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    protected static function newFactory()
    {
        return RoleFactory::new();
    }

    public function scopeForScope($query, ?string $scope)
    {
        if ($scope === null) {
            return $query->whereNull('scope');
        }

        return $query->where('scope', $scope);
    }

    public static function forScope(?string $scope)
    {
        return static::query()->forScope($scope);
    }

    protected function permissionModel(): string
    {
        return config('roles-permissions.models.permission', Permission::class);
    }

    protected function userModel(): string
    {
        return config('roles-permissions.models.user')
            ?? config('auth.providers.users.model')
            ?? 'App\\Models\\User';
    }
}
