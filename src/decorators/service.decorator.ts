import 'reflect-metadata';

export const SERVICE_METADATA_KEY = Symbol('service');
export const INJECT_METADATA_KEY = Symbol('inject');

export interface ServiceMetadata {
  target: any;
  singleton?: boolean;
}

export function Service(singleton: boolean = true) {
  return function (target: any) {
    Reflect.defineMetadata(SERVICE_METADATA_KEY, { target, singleton }, target);
  };
}

export function Inject(token: string) {
  return function (target: any, propertyKey: string | symbol | undefined, parameterIndex: number) {
    const existingTokens = Reflect.getMetadata(INJECT_METADATA_KEY, target) || [];
    existingTokens[parameterIndex] = token;
    Reflect.defineMetadata(INJECT_METADATA_KEY, existingTokens, target);
  };
}
