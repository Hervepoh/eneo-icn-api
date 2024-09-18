import { NextFunction, Request, Response } from 'express';

import { redis } from '../libs/utils/redis';
import prismaClient from '../libs/prismadb';
import NotFoundException from '../exceptions/not-found';
import { ErrorCode } from '../exceptions/http-exception';
import UnprocessableException from '../exceptions/validation';

import { permissionSchema, bulkCreateSchema, bulkDeleteSchema } from '../schema/permissions';
import BadRequestException from '../exceptions/bad-requests';

const key = 'permissions';

//-----------------------------------------------------------------------------
//             CREATE BANK : post /permissions
//-----------------------------------------------------------------------------

// IPermissionRequest
interface IPermissionRequest {
    name: string;
}

// Handling create permission process
export const create =
    async (req: Request, res: Response, next: NextFunction) => {
        // Validate input
        const parsedPermission = permissionSchema.parse(req.body as IPermissionRequest);
        // search if the name already exists
        const isAlready = await prismaClient.permission.findFirst({ where: { name: parsedPermission.name } });
        if (isAlready) {
            throw new UnprocessableException(null, "Duplicate setting name", ErrorCode.RESSOURCE_ALREADY_EXISTS);
        }
        const data = await prismaClient.permission.create({
            data: parsedPermission,
        });
        revalidateService(key);

        res.status(201).json({
            success: true,
            data
        });
    };


//-----------------------------------------------------------------------------
//             GET ALL BANK :  get /permissions
//-----------------------------------------------------------------------------

// Handling the process GET permissions 
export const get =
    async (req: Request, res: Response, next: NextFunction) => {
        let data;
        const redis_data = await redis.get(key);
        if (redis_data) {
            data = JSON.parse(redis_data);
        } else {
            data = await revalidateService(key);
        }

        res.status(200).json({
            success: true,
            data
        });
    }


//-----------------------------------------------------------------------------
//             GET BANK BY ID : get /permissions/:id
//-----------------------------------------------------------------------------

// Handling the process GET permission by ID 
export const getById =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

        const data = await prismaClient.permission.findUnique({
            where: { id: id },
        });
        if (!data) throw new NotFoundException("Permission not found", ErrorCode.RESSOURCE_NOT_FOUND);

        res.status(200).json({
            success: true,
            data
        });

    };

//-----------------------------------------------------------------------------
//             UPDATE BANK : put  /permissions/:id
//-----------------------------------------------------------------------------

// Handling Update permission process
export const update =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

        const parsedPermission = permissionSchema.parse(req.body); // Validate input
        const data = await prismaClient.permission.update({
            where: { id: id },
            data: parsedPermission,
        });
        revalidateService(key);

        res.status(200).json({
            success: true,
            data
        });

    };


//-----------------------------------------------------------------------------
//             DELETE BANK : delete  /permissions/:id
//-----------------------------------------------------------------------------

// Handling delete permission process
export const remove =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

        await prismaClient.permission.delete({
            where: { id: id },
        });
        revalidateService(key);

        res.status(204).send(); // No content

    };


//-----------------------------------------------------------------------------
//             BULK-CREATE BANK : post /permissions
//-----------------------------------------------------------------------------

// IBulkCreateRequest interface definition
interface IBulkCreateRequest {
    data: { name: string }[];
}

// Handling create permission process
export const bulkCreate = async (req: Request, res: Response, next: NextFunction) => {

    // Validate input
    const parsedData = bulkCreateSchema.parse(req.body as IBulkCreateRequest);

    // Check for duplicate permission names
    const existingRessources = await Promise.all(parsedData.data.map(async item => {
        return await prismaClient.permission.findFirst({ where: { name: item.name } });
    }));

    const duplicates = existingRessources.filter(item => item);
    if (duplicates.length > 0) {
        return res.status(422).json({
            success: false,
            message: "Duplicate setting names found",
            duplicates: duplicates.map(item => item?.name)
        });
    }

    // Create permissions
    const createdPermissions = await Promise.all(parsedData.data.map(permission =>
        prismaClient.permission.create({ data: permission })
    ));

    revalidateService(key);

    res.status(201).json({
        success: true,
        data: createdPermissions
    });

};

//-----------------------------------------------------------------------------
//             BULK-DELETE BANK : delete  /permissions/:id
//-----------------------------------------------------------------------------

// IBulkCreateRequest
interface IBulkDeleteRequest {
    data: { id: string }[];
}

// Handling bulk delete permission process
export const bulkRemove = async (req: Request, res: Response, next: NextFunction) => {

    // Validate input using Zod
    const { ids } = bulkDeleteSchema.parse(req.body);

    // Perform bulk delete
    const deleteResult = await prismaClient.permission.deleteMany({
        where: {
            id: { in: ids } // Use 'in' to delete all matching IDs in one query
        }
    });

    revalidateService(key);

    // Send response
    res.status(204).send(); // No content

};

const revalidateService = async (key: string) => {
    const data = await prismaClient.permission.findMany({
        orderBy: {
            createdAt: 'desc',
        },
    });
    await redis.set(key, JSON.stringify(data));
    return data
}