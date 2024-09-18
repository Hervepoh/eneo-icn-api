"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bulkDeleteSchema = exports.bulkCreateSchema = exports.paymentModeSchema = void 0;
const zod_1 = require("zod");
const paymentModeSchema = zod_1.z.object({
    name: zod_1.z.string()
        .min(1, 'Bank name is required')
        .max(100, { message: "Bank name Less than 100 caracters." })
        .regex(/^[a-zA-Z0-9\s]+$/, { message: "The payment mode name can only contain letters, numbers, and spaces." })
});
exports.paymentModeSchema = paymentModeSchema;
// Define the schema for bulk create requests
const bulkCreateSchema = zod_1.z.object({
    data: zod_1.z.array(paymentModeSchema).min(1, { message: "At least one payment mode must be provided." })
});
exports.bulkCreateSchema = bulkCreateSchema;
// Define the schema for bulk delete requests
const bulkDeleteSchema = zod_1.z.object({
    ids: zod_1.z.array(zod_1.z.string()).min(1, { message: "At least one ID must be provided." })
});
exports.bulkDeleteSchema = bulkDeleteSchema;
