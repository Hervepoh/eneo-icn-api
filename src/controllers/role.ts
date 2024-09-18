import { NextFunction, Request, Response } from 'express';

import prismaClient from '../libs/prismadb';
import { bulkCreateSchema, bulkDeleteSchema, roleSchema } from '../schema/roles';
import NotFoundException from '../exceptions/not-found';
import { ErrorCode } from '../exceptions/http-exception';
import { redis } from '../libs/utils/redis';
import BadRequestException from '../exceptions/bad-requests';

const key = 'roles';

//-----------------------------------------------------------------------------
//             CREATE ROLES : post /roles
//-----------------------------------------------------------------------------

// IRoleRequest
interface IRoleRequest {
    name: string;
}

// Handling create role process
export const create =
    async (req: Request, res: Response, next: NextFunction) => {
        // Validate input
        const parsedRole = roleSchema.parse(req.body as IRoleRequest);
        const role = await prismaClient.role.create({
            data: parsedRole,
        });
        revalidateService(key);

        res.status(201).json({
            success: true,
            data: role
        });
    };


//-----------------------------------------------------------------------------
//             GET ALL ROLES :  get /roles
//-----------------------------------------------------------------------------

// Handling the process GET roles 
export const get =
    async (req: Request, res: Response, next: NextFunction) => {
        let data;
        const redis_data = await redis.get(key);
        if (redis_data) {
            data = JSON.parse(redis_data);
        } else {
            data = await revalidateService(key);
        }
        const roles = await prismaClient.role.findMany();
        res.status(200).json({
            success: true,
            data: roles
        });
    };


//-----------------------------------------------------------------------------
//             GET ROLE BY ID : get /roles/:id
//-----------------------------------------------------------------------------

// Handling the process GET role by ID 
export const getById =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

        const role = await prismaClient.role.findUnique({
            where: { id: id },
        });
        if (!role) throw new NotFoundException("Role not found", ErrorCode.RESSOURCE_NOT_FOUND);

        res.status(200).json({
            success: true,
            data: role
        });

    };

//-----------------------------------------------------------------------------
//             UPDATE ROLE : put  /roles/:id
//-----------------------------------------------------------------------------

// Handling Update role process
export const update =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

        const parsedRole = roleSchema.parse(req.body); // Validate input
        const role = await prismaClient.role.update({
            where: { id: id },
            data: parsedRole,
        });
        revalidateService(key);

        res.status(200).json({
            success: true,
            data: role
        });

    };


//-----------------------------------------------------------------------------
//             DELETE ROLE : delete  /roles/:id
//-----------------------------------------------------------------------------

// Handling delete role process
export const remove =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

        await prismaClient.role.delete({
            where: { id: id },
        });
        revalidateService(key);

        res.status(204).send(); // No content

    };


//-----------------------------------------------------------------------------
//             BULK-CREATE ROLE : post /roles
//-----------------------------------------------------------------------------

// IBulkCreateRequest interface definition
interface IBulkCreateRequest {
    data: { name: string }[];
}

// Handling create role process
export const bulkCreate = async (req: Request, res: Response, next: NextFunction) => {

    // Validate input
    const parsedData = bulkCreateSchema.parse(req.body as IBulkCreateRequest);

    // Check for duplicate role names
    const existingRessources = await Promise.all(parsedData.data.map(async item => {
        return await prismaClient.role.findFirst({ where: { name: item.name } });
    }));

    const duplicates = existingRessources.filter(item => item);
    if (duplicates.length > 0) {
        return res.status(422).json({
            success: false,
            message: "Duplicate setting names found",
            duplicates: duplicates.map(item => item?.name)
        });
    }

    // Create roles
    const createdRoles = await Promise.all(parsedData.data.map(role =>
        prismaClient.role.create({ data: role })
    ));

    revalidateService(key);

    res.status(201).json({
        success: true,
        data: createdRoles
    });

};

//-----------------------------------------------------------------------------
//             BULK-DELETE ROLE : delete  /roles/bulk
//-----------------------------------------------------------------------------

// IBulkCreateRequest
interface IBulkDeleteRequest {
    data: { id: string }[];
}

// Handling bulk delete role process
export const bulkRemove = async (req: Request, res: Response, next: NextFunction) => {

    // Validate input using Zod
    const { ids } = bulkDeleteSchema.parse(req.body);

    // Perform bulk delete
    const deleteResult = await prismaClient.role.deleteMany({
        where: {
            id: { in: ids } // Use 'in' to delete all matching IDs in one query
        }
    });

    revalidateService(key);

    // Send response
    res.status(204).send(); // No content

};


//-----------------------------------------------------------------------------
//             ASSIGN PERMISSION TO ROLE : delete  /roles/:id
//-----------------------------------------------------------------------------

// IPermissionAssignRequest
type IPermissionAssignRequest = {
    roleId: string;
    permissionId: string
}

// Function to assign permission to a role
export const assignPermission = async (req: Request, res: Response, next: NextFunction) => {
    const { roleId, permissionId }: IPermissionAssignRequest = req.body;
    if (!roleId || !permissionId) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

    // Check if the role exists
    const role = await prismaClient.role.findUnique({
        where: { id: roleId },
    });
    if (!role) throw new NotFoundException("Role not found", ErrorCode.RESSOURCE_NOT_FOUND);

    // Check if the permission exists
    const permission = await prismaClient.permission.findUnique({
        where: { id: permissionId },
    });
    if (!permission) throw new NotFoundException("Permission not found", ErrorCode.RESSOURCE_NOT_FOUND);

    // Assign the permission to the role
    await prismaClient.rolePermission.create({
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

};


// Function to get all permission assign to a role
export const getPermissions = async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

    // Récupérer le rôle avec ses permissions associées
    const roleWithPermissions = await prismaClient.role.findUnique({
        where: { id: id },
        include: {
            RolePermission: true, // Inclure les permissions associées
        },
    });
    if (!roleWithPermissions) throw new NotFoundException("Role not found", ErrorCode.RESSOURCE_NOT_FOUND);

    res.status(200).json({
        success: true,
        role: {
            id: roleWithPermissions.id,
            name: roleWithPermissions.name,
            permissions: roleWithPermissions.RolePermission, // Retourner les permissions
        },
    });

};


const revalidateService = async (key: string) => {
    const data = await prismaClient.role.findMany({
        orderBy: {
            createdAt: 'desc',
        },
    });
    await redis.set(key, JSON.stringify(data));
    return data
}