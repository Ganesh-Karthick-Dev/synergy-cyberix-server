import 'reflect-metadata';
import multer from 'multer';
import { config } from '../config/env.config';

export const FILE_UPLOAD_METADATA_KEY = Symbol('fileUpload');

export interface FileUploadMetadata {
  fieldName: string;
  maxCount?: number;
  allowedMimeTypes?: string[];
  maxFileSize?: number;
}

export function FileUpload(
  fieldName: string = 'file',
  maxCount: number = 1,
  allowedMimeTypes?: string[],
  maxFileSize?: number
) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const metadata: FileUploadMetadata = {
      fieldName,
      maxCount,
      allowedMimeTypes,
      maxFileSize: maxFileSize || config.upload.maxFileSize
    };

    Reflect.defineMetadata(FILE_UPLOAD_METADATA_KEY, metadata, descriptor.value);
  };
}

export function SingleFile(fieldName: string = 'file') {
  return FileUpload(fieldName, 1);
}

export function MultipleFiles(fieldName: string = 'files', maxCount: number = 5) {
  return FileUpload(fieldName, maxCount);
}

export function ImageUpload(fieldName: string = 'image') {
  return FileUpload(fieldName, 1, ['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
}

export function DocumentUpload(fieldName: string = 'document') {
  return FileUpload(fieldName, 1, [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
  ]);
}
