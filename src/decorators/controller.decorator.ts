import 'reflect-metadata';

export const CONTROLLER_METADATA_KEY = Symbol('controller');
export const ROUTE_METADATA_KEY = Symbol('route');

export interface ControllerMetadata {
  path: string;
  middleware?: any[];
}

export interface RouteMetadata {
  method: 'get' | 'post' | 'put' | 'delete' | 'patch';
  path: string;
  middleware?: any[];
}

export function Controller(path: string, middleware?: any[]) {
  return function (target: any) {
    Reflect.defineMetadata(CONTROLLER_METADATA_KEY, {
      path,
      middleware
    }, target);
  };
}

export function Get(path: string, middleware?: any[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'get',
      path,
      middleware
    }, descriptor.value);
  };
}

export function Post(path: string, middleware?: any[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'post',
      path,
      middleware
    }, descriptor.value);
  };
}

export function Put(path: string, middleware?: any[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'put',
      path,
      middleware
    }, descriptor.value);
  };
}

export function Delete(path: string, middleware?: any[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'delete',
      path,
      middleware
    }, descriptor.value);
  };
}

export function Patch(path: string, middleware?: any[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'patch',
      path,
      middleware
    }, descriptor.value);
  };
}
