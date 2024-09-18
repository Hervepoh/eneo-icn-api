"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPermissions = exports.assignPermission = exports.bulkRemove = exports.bulkCreate = exports.remove = exports.update = exports.getById = exports.get = exports.create = void 0;
const prismadb_1 = __importDefault(require("../libs/prismadb"));
const roles_1 = require("../schema/roles");
const not_found_1 = __importDefault(require("../exceptions/not-found"));
const http_exception_1 = require("../exceptions/http-exception");
const redis_1 = require("../libs/utils/redis");
const bad_requests_1 = __importDefault(require("../exceptions/bad-requests"));
const key = 'roles';
// Handling create role process
const create = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input
    const parsedRole = roles_1.roleSchema.parse(req.body);
    const role = yield prismadb_1.default.role.create({
        data: parsedRole,
    });
    revalidateService(key);
    res.status(201).json({
        success: true,
        data: role
    });
});
exports.create = create;
//-----------------------------------------------------------------------------
//             GET ALL ROLES :  get /roles
//-----------------------------------------------------------------------------
// Handling the process GET roles 
const get = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    let data;
    const redis_data = yield redis_1.redis.get(key);
    if (redis_data) {
        data = JSON.parse(redis_data);
    }
    else {
        data = yield revalidateService(key);
    }
    const roles = yield prismadb_1.default.role.findMany();
    res.status(200).json({
        success: true,
        data: roles
    });
});
exports.get = get;
//-----------------------------------------------------------------------------
//             GET ROLE BY ID : get /roles/:id
//-----------------------------------------------------------------------------
// Handling the process GET role by ID 
const getById = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    const role = yield prismadb_1.default.role.findUnique({
        where: { id: id },
    });
    if (!role)
        throw new not_found_1.default("Role not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    res.status(200).json({
        success: true,
        data: role
    });
});
exports.getById = getById;
//-----------------------------------------------------------------------------
//             UPDATE ROLE : put  /roles/:id
//-----------------------------------------------------------------------------
// Handling Update role process
const update = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    const parsedRole = roles_1.roleSchema.parse(req.body); // Validate input
    const role = yield prismadb_1.default.role.update({
        where: { id: id },
        data: parsedRole,
    });
    revalidateService(key);
    res.status(200).json({
        success: true,
        data: role
    });
});
exports.update = update;
//-----------------------------------------------------------------------------
//             DELETE ROLE : delete  /roles/:id
//-----------------------------------------------------------------------------
// Handling delete role process
const remove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    yield prismadb_1.default.role.delete({
        where: { id: id },
    });
    revalidateService(key);
    res.status(204).send(); // No content
});
exports.remove = remove;
// Handling create role process
const bulkCreate = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input
    const parsedData = roles_1.bulkCreateSchema.parse(req.body);
    // Check for duplicate role names
    const existingRessources = yield Promise.all(parsedData.data.map((item) => __awaiter(void 0, void 0, void 0, function* () {
        return yield prismadb_1.default.role.findFirst({ where: { name: item.name } });
    })));
    const duplicates = existingRessources.filter(item => item);
    if (duplicates.length > 0) {
        return res.status(422).json({
            success: false,
            message: "Duplicate setting names found",
            duplicates: duplicates.map(item => item === null || item === void 0 ? void 0 : item.name)
        });
    }
    // Create roles
    const createdRoles = yield Promise.all(parsedData.data.map(role => prismadb_1.default.role.create({ data: role })));
    revalidateService(key);
    res.status(201).json({
        success: true,
        data: createdRoles
    });
});
exports.bulkCreate = bulkCreate;
// Handling bulk delete role process
const bulkRemove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input using Zod
    const { ids } = roles_1.bulkDeleteSchema.parse(req.body);
    // Perform bulk delete
    const deleteResult = yield prismadb_1.default.role.deleteMany({
        where: {
            id: { in: ids } // Use 'in' to delete all matching IDs in one query
        }
    });
    revalidateService(key);
    // Send response
    res.status(204).send(); // No content
});
exports.bulkRemove = bulkRemove;
// Function to assign permission to a role
const assignPermission = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { roleId, permissionId } = req.body;
    if (!roleId || !permissionId)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    // Check if the role exists
    const role = yield prismadb_1.default.role.findUnique({
        where: { id: roleId },
    });
    if (!role)
        throw new not_found_1.default("Role not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    // Check if the permission exists
    const permission = yield prismadb_1.default.permission.findUnique({
        where: { id: permissionId },
    });
    if (!permission)
        throw new not_found_1.default("Permission not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    // Assign the permission to the role
    yield prismadb_1.default.rolePermission.create({
        data: {
            roleId,
            permissionId,
        },
    });
    revalidateService(key);
    res.status(201).json({
        success: true,
        message: "Permission assigned to role successfully."
    });
});
exports.assignPermission = assignPermission;
// Function to get all permission assign to a role
const getPermissions = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    // Récupérer le rôle avec ses permissions associées
    const roleWithPermissions = yield prismadb_1.default.role.findUnique({
        where: { id: id },
        include: {
            RolePermission: true, // Inclure les permissions associées
        },
    });
    if (!roleWithPermissions)
        throw new not_found_1.default("Role not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    res.status(200).json({
        success: true,
        role: {
            id: roleWithPermissions.id,
            name: roleWithPermissions.name,
            permissions: roleWithPermissions.RolePermission, // Retourner les permissions
        },
    });
});
exports.getPermissions = getPermissions;
const revalidateService = (key) => __awaiter(void 0, void 0, void 0, function* () {
    const data = yield prismadb_1.default.role.findMany({
        orderBy: {
            createdAt: 'desc',
        },
    });
    yield redis_1.redis.set(key, JSON.stringify(data));
    return data;
});
