"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bulkDeleteSchema = exports.bulkCreateSchema = exports.transactionSchema = exports.idSchema = void 0;
const zod_1 = require("zod");
const idSchema = zod_1.z.string().uuid();
exports.idSchema = idSchema;
const transactionSchema = zod_1.z.object({
    reference: zod_1.z.string().optional(),
    userId: zod_1.z.string().uuid(), // Assurez-vous que c'est un UUID
    name: zod_1.z.string()
        .min(1, 'Bank name is required')
        .max(100, { message: "Bank name Less than 100 caracters." })
        .regex(/^[a-zA-Z0-9\s]+$/, { message: "The transaction name can only contain letters, numbers, and spaces." }),
    amount: zod_1.z.number().positive(),
    bankId: zod_1.z.string().uuid('Bank name is required'),
    paymentDate: zod_1.z.date(),
    paymentModeId: zod_1.z.string().uuid(),
    statusId: zod_1.z.string().uuid(),
    validatorId: zod_1.z.string().uuid().optional(),
    createdBy: zod_1.z.string().optional(),
    modifiedBy: zod_1.z.string().optional(),
});
exports.transactionSchema = transactionSchema;
// Define the schema for bulk create requests
const bulkCreateSchema = zod_1.z.object({
    data: zod_1.z.array(transactionSchema).min(1, { message: "At least one transaction must be provided." })
});
exports.bulkCreateSchema = bulkCreateSchema;
// Define the schema for bulk delete requests
const bulkDeleteSchema = zod_1.z.object({
    ids: zod_1.z.array(zod_1.z.string()).min(1, { message: "At least one ID must be provided." })
});
exports.bulkDeleteSchema = bulkDeleteSchema;
