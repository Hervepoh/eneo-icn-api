import { NextFunction, Request, Response } from 'express';

import { redis } from '../libs/utils/redis';
import prismaClient from '../libs/prismadb';
import { ErrorCode } from '../exceptions/http-exception';
import NotFoundException from '../exceptions/not-found';
import UnprocessableException from '../exceptions/validation';

import { paymentModeSchema, bulkCreateSchema, bulkDeleteSchema } from '../schema/paymentModes';
import BadRequestException from '../exceptions/bad-requests';

const key = 'paymentModes';

//-----------------------------------------------------------------------------
//             CREATE BANK : post /paymentModes
//-----------------------------------------------------------------------------

// IPaymentModeRequest
interface IPaymentModeRequest {
    name: string;
}

// Handling create paymentMode process
export const create =
    async (req: Request, res: Response, next: NextFunction) => {
        // Validate input
        const parsedPaymentMode = paymentModeSchema.parse(req.body as IPaymentModeRequest);
        // search if the name already exists //TODO CHECK if it is need
        const isAlready = await prismaClient.paymentMode.findFirst({ where: { name: parsedPaymentMode.name } });
        if (isAlready) {
            throw new UnprocessableException(null, "Duplicate setting name", ErrorCode.RESSOURCE_ALREADY_EXISTS);
        }
        const data = await prismaClient.paymentMode.create({
            data: parsedPaymentMode,
        });
        revalidateService(key);

        res.status(201).json({
            success: true,
            data
        });
    };


//-----------------------------------------------------------------------------
//             GET ALL BANK :  get /paymentModes
//-----------------------------------------------------------------------------

// Handling the process GET paymentModes 
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
//             GET BANK BY ID : get /paymentModes/:id
//-----------------------------------------------------------------------------

// Handling the process GET paymentMode by ID 
export const getById =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

        const data = await prismaClient.paymentMode.findUnique({
            where: { id: id },
        });
        if (!data) throw new NotFoundException("PaymentMode not found", ErrorCode.RESSOURCE_NOT_FOUND);

        res.status(200).json({
            success: true,
            data
        });

    };

//-----------------------------------------------------------------------------
//             UPDATE BANK : put  /paymentModes/:id
//-----------------------------------------------------------------------------

// Handling Update paymentMode process
export const update =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

        const parsedPaymentMode = paymentModeSchema.parse(req.body); // Validate input
        const data = await prismaClient.paymentMode.update({
            where: { id: id },
            data: parsedPaymentMode,
        });
        revalidateService(key);

        res.status(200).json({
            success: true,
            data
        });

    };


//-----------------------------------------------------------------------------
//             DELETE BANK : delete  /paymentModes/:id
//-----------------------------------------------------------------------------

// Handling delete paymentMode process
export const remove =
    async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;
        if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

        await prismaClient.paymentMode.delete({
            where: { id: id },
        });
        revalidateService(key);

        res.status(204).send(); // No content

    };


//-----------------------------------------------------------------------------
//             BULK-CREATE BANK : post /paymentModes
//-----------------------------------------------------------------------------

// IBulkCreateRequest interface definition
interface IBulkCreateRequest {
    data: { name: string }[];
}

// Handling create paymentMode process
export const bulkCreate = async (req: Request, res: Response, next: NextFunction) => {

    // Validate input
    const parsedData = bulkCreateSchema.parse(req.body as IBulkCreateRequest);

    // Check for duplicate paymentMode names
    const existingRessources = await Promise.all(parsedData.data.map(async item => {
        return await prismaClient.paymentMode.findFirst({ where: { name: item.name } });
    }));

    const duplicates = existingRessources.filter(item => item);
    if (duplicates.length > 0) {
        return res.status(422).json({
            success: false,
            message: "Duplicate setting names found",
            duplicates: duplicates.map(item => item?.name)
        });
    }

    // Create paymentModes
    const createdPaymentModes = await Promise.all(parsedData.data.map(paymentMode =>
        prismaClient.paymentMode.create({ data: paymentMode })
    ));

    revalidateService(key);

    res.status(201).json({
        success: true,
        data: createdPaymentModes
    });

};

//-----------------------------------------------------------------------------
//             BULK-DELETE BANK : delete  /paymentModes/:id
//-----------------------------------------------------------------------------

// IBulkCreateRequest
interface IBulkDeleteRequest {
    data: { id: string }[];
}

// Handling bulk delete paymentMode process
export const bulkRemove = async (req: Request, res: Response, next: NextFunction) => {

    // Validate input using Zod
    const { ids } = bulkDeleteSchema.parse(req.body);

    // Perform bulk delete
    const deleteResult = await prismaClient.paymentMode.deleteMany({
        where: {
            id: { in: ids } // Use 'in' to delete all matching IDs in one query
        }
    });

    revalidateService(key);

    // Send response
    res.status(204).send(); // No content

};

const revalidateService = async (key: string) => {
    const data = await prismaClient.paymentMode.findMany({
        orderBy: {
            createdAt: 'desc',
        },
    });
    await redis.set(key, JSON.stringify(data));
    return data
}