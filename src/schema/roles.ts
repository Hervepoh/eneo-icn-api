import { z } from 'zod';

const roleSchema = z.object({
  name: z.string().min(1, 'Role name is required'),
});

// Define the schema for bulk create requests
const bulkCreateSchema = z.object({
  data: z.array(roleSchema).min(1, { message: "At least one role must be provided." })
});

// Define the schema for bulk delete requests
const bulkDeleteSchema = z.object({
  ids: z.array(z.string()).min(1, { message: "At least one ID must be provided." })
});

// Export the schemas
export { roleSchema, bulkCreateSchema , bulkDeleteSchema };