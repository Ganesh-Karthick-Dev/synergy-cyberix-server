import 'reflect-metadata';

export const AUTH_METADATA_KEY = Symbol('auth');

export interface AuthMetadata {
  required: boolean;
  roles?: string[];
}

export function Auth(required: boolean = true, roles?: string[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(AUTH_METADATA_KEY, {
      required,
      roles
    }, descriptor.value);
  };
}

export function RequireAuth(roles?: string[]) {
  return Auth(true, roles);
}

export function OptionalAuth() {
  return Auth(false);
}
