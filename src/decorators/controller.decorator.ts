import 'reflect-metadata';

export const CONTROLLER_METADATA_KEY = Symbol('controller');
export const ROUTE_METADATA_KEY = Symbol('route');

export interface ControllerMetadata {
  path: string;
  target: any;
}

export interface RouteMetadata {
  method: 'get' | 'post' | 'put' | 'delete' | 'patch';
  path: string;
  middleware?: any[];
  target: any;
  propertyKey: string;
}

export function Controller(path: string = '') {
  return function (target: any) {
    Reflect.defineMetadata(CONTROLLER_METADATA_KEY, { path, target }, target);
  };
}

export function Get(path: string = '', middleware: any[] = []) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'get',
      path,
      middleware,
      target,
      propertyKey
    }, target, propertyKey);
  };
}

export function Post(path: string = '', middleware: any[] = []) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'post',
      path,
      middleware,
      target,
      propertyKey
    }, target, propertyKey);
  };
}

export function Put(path: string = '', middleware: any[] = []) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'put',
      path,
      middleware,
      target,
      propertyKey
    }, target, propertyKey);
  };
}

export function Delete(path: string = '', middleware: any[] = []) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(ROUTE_METADATA_KEY, {
      method: 'delete',
      path,
      middleware,
      target,
      propertyKey
    }, target, propertyKey);
  };
}