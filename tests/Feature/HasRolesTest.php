<?php

use Bhhaskin\RolesPermissions\Models\Permission;
use Bhhaskin\RolesPermissions\Models\Role;
use Bhhaskin\RolesPermissions\Tests\Fixtures\Organization;
use Bhhaskin\RolesPermissions\Tests\Fixtures\Post;
use Bhhaskin\RolesPermissions\Tests\Fixtures\Team;
use Bhhaskin\RolesPermissions\Tests\Fixtures\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

it('assigns, checks, and removes roles', function () {
    $user = User::create([
        'name' => 'Role User',
        'email' => sprintf('role-user-%s@example.com', Str::uuid()),
        'password' => bcrypt('password'),
    ]);

    $admin = Role::create(['name' => 'Administrator', 'slug' => 'admin']);
    $moderator = Role::create(['name' => 'Moderator', 'slug' => 'moderator']);

    expect(Str::isUuid($admin->uuid))->toBeTrue();
    expect(Str::isUuid($moderator->uuid))->toBeTrue();

    $user->assignRole($admin, $moderator);
    $user->refresh();

    expect($user->roles)->toHaveCount(2);
    expect($user->hasRole('admin'))->toBeTrue();
    expect($user->hasAnyRole('admin', 'editor'))->toBeTrue();
    expect($user->hasAllRoles('admin', 'moderator'))->toBeTrue();

    $user->removeRole($moderator);
    $user->refresh();

    expect($user->hasRole('moderator'))->toBeFalse();
    expect($user->roles)->toHaveCount(1);
});

it('builds roles and permissions via factories', function () {
    $role = Role::factory()->create();
    $permission = Permission::factory()->create();

    $role->permissions()->attach($permission);

    expect($role->uuid)->toBeString()->not->toBeEmpty();
    expect($permission->uuid)->toBeString()->not->toBeEmpty();
    expect($role->permissions)->toHaveCount(1);
});

it('enforces role scopes for different models', function () {
    config()->set('roles-permissions.object_permissions.enabled', true);
    config()->set('roles-permissions.role_scopes', [
        'team' => Team::class,
        'organization' => Organization::class,
    ]);

    $user = User::create([
        'name' => 'Scoped Role User',
        'email' => sprintf('scoped-roles-%s@example.com', Str::uuid()),
        'password' => bcrypt('password'),
    ]);

    $team = Team::create(['name' => 'Alpha Team']);
    $organization = Organization::create(['name' => 'Gamma Org']);

    $teamRole = Role::factory()->forScope('team')->create([
        'name' => 'Team Manager',
        'slug' => 'manager',
    ]);

    $orgRole = Role::factory()->forScope('organization')->create([
        'name' => 'Org Manager',
        'slug' => 'manager',
    ]);

    $globalRole = Role::factory()->create([
        'name' => 'Global Admin',
        'slug' => 'global-admin',
    ]);

    expect(Role::forScope('team')->count())->toBe(1);
    expect(Role::forScope('organization')->count())->toBe(1);
    expect(Role::forScope(null)->count())->toBeGreaterThanOrEqual(1);

    $user->assignRole($teamRole, $team);
    $user->assignRole($globalRole);

    expect($user->hasRole('manager', $team))->toBeTrue();
    expect($user->hasRole('manager', $organization))->toBeFalse();
    expect($user->hasRole('global-admin', $team))->toBeTrue();

    expect(fn () => $user->assignRole($teamRole))->toThrow(\LogicException::class);
    expect(fn () => $user->assignRole($orgRole, $team))->toThrow(\LogicException::class);

    $user->assignRole('manager', $organization);
    expect($user->hasRole($orgRole, $organization))->toBeTrue();
});

it('handles direct and inherited permissions', function () {
    $user = User::create([
        'name' => 'Permission User',
        'email' => sprintf('permission-user-%s@example.com', Str::uuid()),
        'password' => bcrypt('password'),
    ]);

    $role = Role::create(['name' => 'Editor', 'slug' => 'editor']);
    $publish = Permission::create(['name' => 'Publish Posts', 'slug' => 'publish-posts']);
    $feature = Permission::create(['name' => 'Feature Posts', 'slug' => 'feature-posts']);

    expect(Str::isUuid($publish->uuid))->toBeTrue();
    expect(Str::isUuid($feature->uuid))->toBeTrue();

    $role->permissions()->attach($publish);
    $user->assignRole($role);
    $user->givePermission($feature);
    $user->refresh();

    expect($user->hasPermission('publish-posts'))->toBeTrue(); // via role
    expect($user->hasPermission('feature-posts'))->toBeTrue(); // direct

    $user->revokePermission($feature);
    $user->refresh();

    expect($user->hasPermission('feature-posts'))->toBeFalse();
});

it('supports object level roles and permissions when enabled', function () {
    config()->set('roles-permissions.object_permissions.enabled', true);

    $user = User::create([
        'name' => 'Scoped User',
        'email' => sprintf('scoped-user-%s@example.com', Str::uuid()),
        'password' => bcrypt('password'),
    ]);

    $post = Post::create(['title' => 'Scoped Post']);
    $otherPost = Post::create(['title' => 'Another Post']);

    $editor = Role::create(['name' => 'Project Editor', 'slug' => 'project-editor']);
    $approve = Permission::create(['name' => 'Approve Post', 'slug' => 'approve-post']);
    $feature = Permission::create(['name' => 'Feature Scoped Post', 'slug' => 'feature-scoped-post']);

    $editor->permissions()->attach($approve);

    $user->assignRole($editor, $post);
    $user->givePermission($feature, $post);
    $user->refresh();

    expect($user->hasRole('project-editor'))->toBeFalse();
    expect($user->hasRole('project-editor', $post))->toBeTrue();
    expect($user->hasRole('project-editor', $otherPost))->toBeFalse();

    expect($user->hasPermission('approve-post'))->toBeFalse();
    expect($user->hasPermission('approve-post', $post))->toBeTrue();
    expect($user->hasPermission('approve-post', $otherPost))->toBeFalse();

    expect($user->hasDirectPermission('feature-scoped-post'))->toBeFalse();
    expect($user->hasDirectPermission('feature-scoped-post', $post))->toBeTrue();
    expect($user->hasDirectPermission('feature-scoped-post', $otherPost))->toBeFalse();

    expect(Gate::forUser($user)->allows('feature-scoped-post', $post))->toBeTrue();
    expect(Gate::forUser($user)->allows('feature-scoped-post', $otherPost))->toBeFalse();

    $user->revokePermission($feature, $post);
    $user->refresh();

    expect($user->hasPermission('feature-scoped-post', $post))->toBeFalse();

    $user->removeRole($editor, $post);
    $user->refresh();

    expect($user->hasRole('project-editor', $post))->toBeFalse();
});

it('syncs roles for a specific context when object permissions are enabled', function () {
    config(['roles-permissions.object_permissions.enabled' => true]);

    $user = User::create(['name' => 'Alice', 'email' => 'alice@example.com', 'password' => 'password']);
    $post = Post::create(['title' => 'Post 1']);

    $admin = Role::create(['name' => 'Admin', 'slug' => 'admin']);
    $editor = Role::create(['name' => 'Editor', 'slug' => 'editor']);
    $viewer = Role::create(['name' => 'Viewer', 'slug' => 'viewer']);

    // Assign admin role to user for this post
    $user->assignRole($admin, $post);
    $user->refresh();

    expect($user->hasRole('admin', $post))->toBeTrue();
    expect($user->hasRole('editor', $post))->toBeFalse();

    // Sync to editor role - should replace admin with editor
    $user->syncRoles($editor, $post);
    $user->refresh();

    expect($user->hasRole('admin', $post))->toBeFalse();
    expect($user->hasRole('editor', $post))->toBeTrue();

    // Sync to viewer role - should replace editor with viewer
    $user->syncRoles($viewer, $post);
    $user->refresh();

    expect($user->hasRole('editor', $post))->toBeFalse();
    expect($user->hasRole('viewer', $post))->toBeTrue();
});
