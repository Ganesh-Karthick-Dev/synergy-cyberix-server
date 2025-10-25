import 'reflect-metadata';

export const HTTP_METHOD_METADATA_KEY = Symbol('httpMethod');
export const ROUTE_PATH_METADATA_KEY = Symbol('routePath');
export const MIDDLEWARE_METADATA_KEY = Symbol('middleware');

export enum HttpMethod {
  GET = 'get',
  POST = 'post',
  PUT = 'put',
  DELETE = 'delete',
  PATCH = 'patch'
}

export function createMethodDecorator(method: HttpMethod) {
  return function (path: string = '', middleware?: any[]) {
    return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
      Reflect.defineMetadata(HTTP_METHOD_METADATA_KEY, method, descriptor.value);
      Reflect.defineMetadata(ROUTE_PATH_METADATA_KEY, path, descriptor.value);
      Reflect.defineMetadata(MIDDLEWARE_METADATA_KEY, middleware || [], descriptor.value);
    };
  };
}

export const Get = createMethodDecorator(HttpMethod.GET);
export const Post = createMethodDecorator(HttpMethod.POST);
export const Put = createMethodDecorator(HttpMethod.PUT);
export const Delete = createMethodDecorator(HttpMethod.DELETE);
export const Patch = createMethodDecorator(HttpMethod.PATCH);
