import { Router } from 'express';
import { CONTROLLER_METADATA_KEY, ROUTE_METADATA_KEY } from '../decorators/controller.decorator';
import { VALIDATION_METADATA_KEY } from '../decorators/validation.decorator';
import { container } from '../container/container';
import { validate } from '../middlewares/validation.middleware';

export class RouteFactory {
  static createRoutes(controllers: any[]): Router {
    const router = Router();

    controllers.forEach(ControllerClass => {
      const controllerMetadata = Reflect.getMetadata(CONTROLLER_METADATA_KEY, ControllerClass);
      if (!controllerMetadata) return;

      const controllerInstance = container.resolve(ControllerClass.name) as any;
      const controllerPath = controllerMetadata.path;

      // Get all method names from the controller
      const methodNames = Object.getOwnPropertyNames(ControllerClass.prototype)
        .filter(name => name !== 'constructor');

      methodNames.forEach(methodName => {
        const routeMetadata = Reflect.getMetadata(ROUTE_METADATA_KEY, ControllerClass.prototype, methodName);
        if (!routeMetadata) return;

        const validationMetadata = Reflect.getMetadata(VALIDATION_METADATA_KEY, ControllerClass.prototype, methodName);
        
        const fullPath = controllerPath + routeMetadata.path;
        const handler = controllerInstance[methodName].bind(controllerInstance);
        
        // Combine middleware
        const middleware = [...(routeMetadata.middleware || [])];
        if (validationMetadata) {
          middleware.push(validate(validationMetadata.rules));
        }

        // Register the route with proper typing
        const method = routeMetadata.method as keyof Router;
        (router[method] as any)(fullPath, ...middleware, handler);
      });
    });

    return router;
  }
}
