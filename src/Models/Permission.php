<?php

namespace Bhhaskin\RolesPermissions\Models;

use Bhhaskin\RolesPermissions\Database\Factories\PermissionFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Str;

class Permission extends Model
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
        return config('roles-permissions.tables.permissions', parent::getTable());
    }

    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            $this->roleModel(),
            config('roles-permissions.tables.permission_role', 'permission_role')
        )->withTimestamps();
    }

    public function users(): BelongsToMany
    {
        return $this->belongsToMany(
            $this->userModel(),
            config('roles-permissions.tables.permission_user', 'permission_user')
        )->withTimestamps();
    }

    protected static function booted(): void
    {
        static::creating(function (self $permission) {
            if (! $permission->uuid) {
                $permission->uuid = (string) Str::uuid();
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
        return PermissionFactory::new();
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

    protected function roleModel(): string
    {
        return config('roles-permissions.models.role', Role::class);
    }

    protected function userModel(): string
    {
        return config('roles-permissions.models.user')
            ?? config('auth.providers.users.model')
            ?? 'App\\Models\\User';
    }
}
