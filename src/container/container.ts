import 'reflect-metadata';
import { SERVICE_METADATA_KEY, INJECT_METADATA_KEY } from '../decorators/service.decorator';

export class Container {
  private services = new Map<string, any>();
  private singletons = new Map<string, any>();

  register<T>(token: string, factory: () => T, singleton: boolean = true): void {
    this.services.set(token, { factory, singleton });
  }

  resolve<T>(token: string): T {
    const service = this.services.get(token);
    if (!service) {
      throw new Error(`Service ${token} not found`);
    }

    if (service.singleton) {
      if (!this.singletons.has(token)) {
        this.singletons.set(token, service.factory());
      }
      return this.singletons.get(token);
    }

    return service.factory();
  }

  autoRegister(target: any): void {
    const metadata = Reflect.getMetadata(SERVICE_METADATA_KEY, target);
    if (metadata) {
      const token = target.name;
      this.register(token, () => {
        const dependencies = this.resolveDependencies(target);
        return new target(...dependencies);
      }, metadata.singleton);
    }
  }

  resolveDependencies(target: any): any[] {
    const tokens = Reflect.getMetadata(INJECT_METADATA_KEY, target) || [];
    return tokens.map((token: string) => this.resolve(token));
  }
}

export const container = new Container();
