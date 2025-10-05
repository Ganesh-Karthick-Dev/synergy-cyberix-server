import 'reflect-metadata';
import { body } from 'express-validator';

export const VALIDATION_METADATA_KEY = Symbol('validation');

export interface ValidationMetadata {
  rules: any[];
  target: any;
  propertyKey: string;
}

export function Validate(rules: any[]) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata(VALIDATION_METADATA_KEY, {
      rules,
      target,
      propertyKey
    }, target, propertyKey);
  };
}

// Common validation rules
export const ValidationRules = {
  email: () => body('email').isEmail().normalizeEmail().withMessage('Please provide a valid organization email'),
  firstName: () => body('firstName').isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters'),
  lastName: () => body('lastName').isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters'),
  phone: () => body('phone').matches(/^[\+]?[1-9][\d]{0,15}$/).withMessage('Please provide a valid phone number'),
  subscriptionType: () => body('subscriptionType').optional().isIn(['FREE', 'PRO', 'PRO_PLUS']).withMessage('Subscription type must be FREE, PRO, or PRO_PLUS')
};

export const RegisterUserValidation = [
  ValidationRules.email(),
  ValidationRules.firstName(),
  ValidationRules.lastName(),
  ValidationRules.phone(),
  ValidationRules.subscriptionType()
];
