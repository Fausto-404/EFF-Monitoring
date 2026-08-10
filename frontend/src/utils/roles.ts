import type { User } from '../api/types';

export function userRoles(user: Pick<User, 'role' | 'roles'> | null | undefined) {
  const roles = Array.isArray(user?.roles) && user.roles.length ? user.roles : (user?.role ? [user.role] : []);
  return Array.from(new Set(roles.filter(Boolean)));
}

export function hasRole(user: Pick<User, 'role' | 'roles'> | null | undefined, role: string) {
  return userRoles(user).includes(role);
}

export function hasAnyRole(user: Pick<User, 'role' | 'roles'> | null | undefined, roles: string[]) {
  const owned = userRoles(user);
  return roles.some((role) => owned.includes(role));
}

export function isOnlyViewer(user: Pick<User, 'role' | 'roles'> | null | undefined) {
  const roles = userRoles(user);
  return roles.length === 1 && roles[0] === 'viewer';
}
