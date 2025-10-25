import 'reflect-metadata';

export const MIDDLEWARE_METADATA_KEY = Symbol('middleware');

export function Use(middleware: any | any[]) {
  return function (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) {
    const middlewares = Array.isArray(middleware) ? middleware : [middleware];
    
    if (descriptor) {
      // Method-level middleware
      const existingMiddleware = Reflect.getMetadata(MIDDLEWARE_METADATA_KEY, descriptor.value) || [];
      Reflect.defineMetadata(MIDDLEWARE_METADATA_KEY, [...existingMiddleware, ...middlewares], descriptor.value);
    } else {
      // Class-level middleware
      const existingMiddleware = Reflect.getMetadata(MIDDLEWARE_METADATA_KEY, target) || [];
      Reflect.defineMetadata(MIDDLEWARE_METADATA_KEY, [...existingMiddleware, ...middlewares], target);
    }
  };
}

export function UseAuth(roles?: string[]) {
  return Use((req: any, res: any, next: any) => {
    // This would be replaced with actual auth middleware
    next();
  });
}

export function UseValidation(validators: any[]) {
  return Use(validators);
}
