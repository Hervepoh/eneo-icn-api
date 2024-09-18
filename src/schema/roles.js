"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bulkDeleteSchema = exports.bulkCreateSchema = exports.roleSchema = void 0;
const zod_1 = require("zod");
const roleSchema = zod_1.z.object({
    name: zod_1.z.string().min(1, 'Role name is required'),
});
exports.roleSchema = roleSchema;
// Define the schema for bulk create requests
const bulkCreateSchema = zod_1.z.object({
    data: zod_1.z.array(roleSchema).min(1, { message: "At least one role must be provided." })
});
exports.bulkCreateSchema = bulkCreateSchema;
// Define the schema for bulk delete requests
const bulkDeleteSchema = zod_1.z.object({
    ids: zod_1.z.array(zod_1.z.string()).min(1, { message: "At least one ID must be provided." })
});
exports.bulkDeleteSchema = bulkDeleteSchema;
