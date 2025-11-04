<?php

namespace Bhhaskin\RolesPermissions\Traits;

use Bhhaskin\RolesPermissions\Exceptions\ObjectPermissionsDisabledException;
use Bhhaskin\RolesPermissions\Exceptions\RoleScopeMismatchException;
use Illuminate\Database\Eloquent\Model as EloquentModel;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

trait HasRoles
{
    public function roles(): BelongsToMany
    {
        $relation = $this->belongsToMany(
            $this->getRoleClass(),
            config('roles-permissions.tables.role_user', 'role_user')
        )->withTimestamps();

        if ($this->objectPermissionsEnabled()) {
            [$typeColumn, $idColumn] = $this->objectMorphColumns();
            $relation->withPivot($typeColumn, $idColumn);
        }

        return $relation;
    }

    public function permissions(): BelongsToMany
    {
        $relation = $this->belongsToMany(
            $this->getPermissionClass(),
            config('roles-permissions.tables.permission_user', 'permission_user')
        )->withTimestamps();

        if ($this->objectPermissionsEnabled()) {
            [$typeColumn, $idColumn] = $this->objectMorphColumns();
            $relation->withPivot($typeColumn, $idColumn);
        }

        return $relation;
    }

    public function assignRole(...$roles): self
    {
        $model = $this->extractModelArgument($roles, 'role');
        $roles = $this->prepareRoles($roles, $model, true);

        if ($roles->isEmpty()) {
            return $this;
        }

        $this->roles()->syncWithoutDetaching($this->formatSyncData($roles, $model));

        return $this;
    }

    public function removeRole(...$roles): self
    {
        $model = $this->extractModelArgument($roles, 'role');
        $roles = $this->prepareRoles($roles, $model, true);

        if ($roles->isEmpty()) {
            return $this;
        }

        $relation = $this->roles();
        $this->scopeRelationToContext($relation, $model);
        $relation->detach($roles->map(fn (EloquentModel $role) => $role->getKey())->all());

        return $this;
    }

    public function syncRoles(...$roles): self
    {
        $model = $this->extractModelArgument($roles, 'role');
        $roles = $this->prepareRoles($roles, $model, true);
        $roleIds = $roles->map(fn (EloquentModel $role) => $role->getKey())->all();

        if (! $this->objectPermissionsEnabled() || ! $model) {
            $this->roles()->sync($roleIds);

            return $this;
        }

        $this->detachRoleAssignmentsNotInContext($model, $roleIds);

        if (! empty($roleIds)) {
            $this->roles()->syncWithoutDetaching($this->formatSyncData($roles, $model));
        }

        return $this;
    }

    public function givePermission(...$permissions): self
    {
        $model = $this->extractModelArgument($permissions, 'permission');
        $permissions = $this->preparePermissions($permissions);

        if ($permissions->isEmpty()) {
            return $this;
        }

        $this->permissions()->syncWithoutDetaching($this->formatSyncData($permissions, $model));

        return $this;
    }

    public function revokePermission(...$permissions): self
    {
        $model = $this->extractModelArgument($permissions, 'permission');
        $permissions = $this->preparePermissions($permissions);

        if ($permissions->isEmpty()) {
            return $this;
        }

        $relation = $this->permissions();
        $this->scopeRelationToContext($relation, $model);
        $relation->detach($permissions->map(fn (EloquentModel $permission) => $permission->getKey())->all());

        return $this;
    }

    public function syncPermissions(...$permissions): self
    {
        $model = $this->extractModelArgument($permissions, 'permission');
        $permissions = $this->preparePermissions($permissions);
        $permissionIds = $permissions->map(fn (EloquentModel $permission) => $permission->getKey())->all();

        if (! $this->objectPermissionsEnabled() || ! $model) {
            $this->permissions()->sync($permissionIds);

            return $this;
        }

        $this->detachPermissionAssignmentsNotInContext($model, $permissionIds);

        if (! empty($permissionIds)) {
            $this->permissions()->syncWithoutDetaching($this->formatSyncData($permissions, $model));
        }

        return $this;
    }

    public function hasRole(string|int|EloquentModel $role, ?EloquentModel $model = null): bool
    {
        $this->ensureObjectPermissionsEnabled($model);

        $role = $this->resolveRole($role, $model);

        if (! $role) {
            return false;
        }

        if ($this->relationLoaded('roles')) {
            return $this->roles->contains(function (EloquentModel $assignedRole) use ($role, $model) {
                if (! $assignedRole->is($role)) {
                    return false;
                }

                return $this->pivotMatchesModel($assignedRole->pivot ?? null, $model, true);
            });
        }

        $relation = $this->roles()->whereKey($role->getKey());

        if ($model) {
            $this->scopeRelationToContext($relation, $model, true);
        } elseif ($this->objectPermissionsEnabled()) {
            $this->scopeRelationToContext($relation, null);
        }

        return $relation->exists();
    }

    public function hasAnyRole(...$roles): bool
    {
        $model = $this->extractModelArgument($roles, 'role');
        $resolvedRoles = $this->prepareRoles($roles, $model);

        if ($resolvedRoles->isEmpty()) {
            return false;
        }

        return $resolvedRoles->contains(fn (EloquentModel $role) => $this->hasRole($role, $model));
    }

    public function hasAllRoles(...$roles): bool
    {
        $model = $this->extractModelArgument($roles, 'role');
        $resolvedRoles = $this->prepareRoles($roles, $model);

        if ($resolvedRoles->isEmpty()) {
            return false;
        }

        return $resolvedRoles->every(fn (EloquentModel $role) => $this->hasRole($role, $model));
    }

    public function hasPermission(string|int|EloquentModel $permission, ?EloquentModel $model = null): bool
    {
        $this->ensureObjectPermissionsEnabled($model);

        $permission = $this->resolvePermission($permission);

        if (! $permission) {
            return false;
        }

        return $this->hasDirectPermissionInstance($permission, $model)
            || $this->hasPermissionThroughRole($permission, $model);
    }

    public function hasDirectPermission(string|int|EloquentModel $permission, ?EloquentModel $model = null): bool
    {
        $this->ensureObjectPermissionsEnabled($model);

        $permission = $this->resolvePermission($permission);

        if (! $permission) {
            return false;
        }

        return $this->hasDirectPermissionInstance($permission, $model);
    }

    public function hasPermissionThroughRole(EloquentModel $permission, ?EloquentModel $model = null): bool
    {
        $this->ensureObjectPermissionsEnabled($model);

        if ($this->relationLoaded('roles')) {
            return $this->roles
                ->filter(fn (EloquentModel $role) => $this->pivotMatchesModel($role->pivot ?? null, $model, true))
                ->contains(function (EloquentModel $role) use ($permission) {
                    if ($role->relationLoaded('permissions')) {
                        return $role->permissions->contains(fn (EloquentModel $rolePermission) => $rolePermission->is($permission));
                    }

                    return $role->permissions()->whereKey($permission->getKey())->exists();
                });
        }

        $relation = $this->roles()
            ->whereHas('permissions', fn ($query) => $query->whereKey($permission->getKey()));

        if ($model) {
            $this->scopeRelationToContext($relation, $model, true);
        } elseif ($this->objectPermissionsEnabled()) {
            $this->scopeRelationToContext($relation, null);
        }

        return $relation->exists();
    }

    protected function hasDirectPermissionInstance(EloquentModel $permission, ?EloquentModel $model = null): bool
    {
        if ($this->relationLoaded('permissions')) {
            return $this->permissions
                ->filter(fn (EloquentModel $assignedPermission) => $assignedPermission->is($permission))
                ->contains(fn (EloquentModel $assignedPermission) => $this->pivotMatchesModel($assignedPermission->pivot ?? null, $model, true));
        }

        $relation = $this->permissions()->whereKey($permission->getKey());

        if ($model) {
            $this->scopeRelationToContext($relation, $model, true);
        } elseif ($this->objectPermissionsEnabled()) {
            $this->scopeRelationToContext($relation, null);
        }

        return $relation->exists();
    }

    protected function prepareRoles(array $roles, ?EloquentModel $context = null, bool $enforceScope = false): Collection
    {
        return collect($roles)
            ->flatten()
            ->map(fn ($role) => $this->resolveRole($role, $context, $enforceScope))
            ->filter()
            ->values();
    }

    protected function preparePermissions(array $permissions): Collection
    {
        return collect($permissions)
            ->flatten()
            ->map(fn ($permission) => $this->resolvePermission($permission))
            ->filter()
            ->values();
    }

    protected function resolveRole(string|int|EloquentModel $role, ?EloquentModel $context = null, bool $enforceScope = false): ?EloquentModel
    {
        $roleClass = $this->getRoleClass();

        if ($role instanceof $roleClass) {
            return $this->filterRoleByContext($role, $context, $enforceScope);
        }

        if ($role instanceof EloquentModel) {
            return null;
        }

        $query = $roleClass::query();

        if (is_numeric($role)) {
            $result = $query->whereKey($role)->first();

            return $this->filterRoleByContext($result, $context, $enforceScope);
        }

        $query->where(function ($q) use ($role) {
            $q->where('slug', $role)
                ->orWhere('name', $role);
        });

        $result = $this->resolveRoleForContext($query, $context);

        return $this->filterRoleByContext($result, $context, $enforceScope);
    }

    protected function resolvePermission(string|int|EloquentModel $permission): ?EloquentModel
    {
        $permissionClass = $this->getPermissionClass();

        if ($permission instanceof $permissionClass) {
            return $permission;
        }

        if ($permission instanceof EloquentModel) {
            return null;
        }

        $query = $permissionClass::query();

        if (is_numeric($permission)) {
            return $query->whereKey($permission)->first();
        }

        return $query
            ->where('slug', $permission)
            ->orWhere('name', $permission)
            ->first();
    }

    protected function getRoleClass(): string
    {
        return config('roles-permissions.models.role', 'Bhhaskin\\RolesPermissions\\Models\\Role');
    }

    protected function getPermissionClass(): string
    {
        return config('roles-permissions.models.permission', 'Bhhaskin\\RolesPermissions\\Models\\Permission');
    }

    protected function resolveRoleForContext($query, ?EloquentModel $context = null): ?EloquentModel
    {
        if (! $context) {
            return (clone $query)->whereNull('scope')->first();
        }

        $scope = $this->determineRoleScope($context);

        if ($scope === null) {
            return (clone $query)->whereNull('scope')->first();
        }

        $scoped = (clone $query)->where('scope', $scope)->first();

        return $scoped ?: (clone $query)->whereNull('scope')->first();
    }

    protected function filterRoleByContext(?EloquentModel $role, ?EloquentModel $context, bool $enforceScope): ?EloquentModel
    {
        if (! $role) {
            return null;
        }

        if ($this->roleMatchesContext($role, $context)) {
            return $role;
        }

        if ($enforceScope) {
            $roleScope = $role->scope ?? null;
            $contextScope = $context ? $this->determineRoleScope($context) : null;
            throw RoleScopeMismatchException::make((string) $roleScope, $contextScope);
        }

        return null;
    }

    protected function roleMatchesContext(EloquentModel $role, ?EloquentModel $context = null): bool
    {
        $roleScope = $role->scope ?? null;

        if ($roleScope === null) {
            return true;
        }

        if (! $context) {
            return false;
        }

        $contextScope = $this->determineRoleScope($context);

        return $contextScope !== null && $roleScope === $contextScope;
    }

    protected function extractModelArgument(array &$arguments, string $type): ?EloquentModel
    {
        if (empty($arguments)) {
            return null;
        }

        $candidate = end($arguments);

        if (! $candidate instanceof EloquentModel) {
            return null;
        }

        $excludedClass = match ($type) {
            'role' => $this->getRoleClass(),
            'permission' => $this->getPermissionClass(),
            default => null,
        };

        if ($excludedClass && $candidate instanceof $excludedClass) {
            return null;
        }

        array_pop($arguments);
        $this->ensureObjectPermissionsEnabled($candidate);

        return $candidate;
    }

    protected function ensureObjectPermissionsEnabled(?EloquentModel $model): void
    {
        if ($model && ! $this->objectPermissionsEnabled()) {
            throw ObjectPermissionsDisabledException::make();
        }
    }

    protected function objectPermissionsEnabled(): bool
    {
        return (bool) config('roles-permissions.object_permissions.enabled', false);
    }

    protected function objectMorphColumns(): array
    {
        $config = config('roles-permissions.object_permissions.columns', []);

        return [
            $config['type'] ?? 'model_type',
            $config['id'] ?? 'model_id',
        ];
    }

    protected function determineRoleScope(?EloquentModel $model): ?string
    {
        if (! $model) {
            return null;
        }

        $scopes = (array) config('roles-permissions.role_scopes', []);

        foreach ($scopes as $key => $value) {
            if (is_int($key) && is_string($value) && class_exists($value) && is_a($model, $value)) {
                return Str::snake(class_basename($value));
            }

            if (is_string($key) && is_string($value) && class_exists($value) && is_a($model, $value)) {
                return $key;
            }

            if (is_string($key) && class_exists($key) && is_a($model, $key)) {
                return is_string($value) ? $value : Str::snake(class_basename($key));
            }
        }

        return Str::snake(class_basename($model));
    }

    protected function pivotAttributesForModel(EloquentModel $model): array
    {
        [$typeColumn, $idColumn] = $this->objectMorphColumns();

        return [
            $typeColumn => $model->getMorphClass(),
            $idColumn => $model->getKey(),
        ];
    }

    protected function scopeRelationToContext(BelongsToMany $relation, ?EloquentModel $model, bool $includeGlobal = false): void
    {
        if (! $this->objectPermissionsEnabled()) {
            return;
        }

        [$typeColumn, $idColumn] = $this->objectMorphColumns();
        $pivotTable = $relation->getTable();

        if ($model) {
            $relation->where(function ($query) use ($pivotTable, $typeColumn, $idColumn, $model, $includeGlobal) {
                $query->where("{$pivotTable}.{$typeColumn}", $model->getMorphClass())
                    ->where("{$pivotTable}.{$idColumn}", $model->getKey());

                if ($includeGlobal) {
                    $query->orWhere(function ($query) use ($pivotTable, $typeColumn, $idColumn) {
                        $query->whereNull("{$pivotTable}.{$typeColumn}")
                            ->whereNull("{$pivotTable}.{$idColumn}");
                    });
                }
            });

            return;
        }

        $relation->whereNull("{$pivotTable}.{$typeColumn}")
            ->whereNull("{$pivotTable}.{$idColumn}");
    }

    protected function pivotMatchesModel($pivot, ?EloquentModel $model, bool $includeGlobal = false): bool
    {
        if (! $this->objectPermissionsEnabled()) {
            return true;
        }

        [$typeColumn, $idColumn] = $this->objectMorphColumns();

        $pivotType = $pivot->{$typeColumn} ?? null;
        $pivotId = $pivot->{$idColumn} ?? null;

        if (! $model) {
            return $pivotType === null && $pivotId === null;
        }

        if ($pivotType === $model->getMorphClass() && (string) $pivotId === (string) $model->getKey()) {
            return true;
        }

        return $includeGlobal && $pivotType === null && $pivotId === null;
    }

    protected function formatSyncData(Collection $models, ?EloquentModel $context = null): array
    {
        if ($models->isEmpty()) {
            return [];
        }

        if (! $this->objectPermissionsEnabled()) {
            return $models->map(fn (EloquentModel $model) => $model->getKey())->all();
        }

        if ($context) {
            $attributes = $this->pivotAttributesForModel($context);

            return $models
                ->mapWithKeys(fn (EloquentModel $model) => [$model->getKey() => $attributes])
                ->all();
        }

        return $models
            ->mapWithKeys(fn (EloquentModel $model) => [$model->getKey() => []])
            ->all();
    }

    protected function detachRoleAssignmentsNotInContext(EloquentModel $model, array $roleIds): void
    {
        [$typeColumn, $idColumn] = $this->objectMorphColumns();

        $relation = $this->roles();
        $pivotKey = $relation->getRelatedPivotKeyName();

        $query = $relation->wherePivot($typeColumn, $model->getMorphClass())
            ->wherePivot($idColumn, $model->getKey());

        if (! empty($roleIds)) {
            $query = $query->wherePivotNotIn($pivotKey, $roleIds);
        }

        $query->detach();
    }

    protected function detachPermissionAssignmentsNotInContext(EloquentModel $model, array $permissionIds): void
    {
        [$typeColumn, $idColumn] = $this->objectMorphColumns();

        $relation = $this->permissions();
        $pivotKey = $relation->getRelatedPivotKeyName();

        $query = $relation->wherePivot($typeColumn, $model->getMorphClass())
            ->wherePivot($idColumn, $model->getKey());

        if (! empty($permissionIds)) {
            $query = $query->wherePivotNotIn($pivotKey, $permissionIds);
        }

        $query->detach();
    }
}
