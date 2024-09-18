import { NextFunction, Request, Response } from "express";


import { appConfig } from "../config/app.config";
import { redis } from "../libs/utils/redis";
import { parseDMY } from "../libs/utils/formatter";
import BadRequestException from "../exceptions/bad-requests";
import { ErrorCode } from "../exceptions/http-exception";
import prismaClient from "../libs/prismadb";
import NotFoundException from "../exceptions/not-found";
import UnauthorizedException from "../exceptions/unauthorized";


export const get =
  async (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

    const datas = await prismaClient.transactionDetail.findMany({
      where: { transactionId: id },
      orderBy: { createdAt: 'desc' }
    });

    return res.status(200).json({
      success: true,
      data: datas,
    });

  };


export const bulkCreate =
  async (req: Request, res: Response, next: NextFunction) => {

    const id = req.params.id;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

    // check if the user id is valid
    const user = await prismaClient.user.findUnique({
      where: { id: req.user?.id }
    });
    if (!user) throw new UnauthorizedException("Unauthorize ressource", ErrorCode.UNAUTHORIZE);

    //TODO: check if the user is the assignee of the record
    const isAssignTo = await prismaClient.transaction.findFirst({
      where: {
        id: id,
        userId: req.user?.id,
      }
    });
    if (!isAssignTo) throw new UnauthorizedException("Unauthorize ressource", ErrorCode.UNAUTHORIZE);

    let data = req.body;

    if (!Array.isArray(data) || data.length === 0) {
      throw new BadRequestException('Invalid params format', ErrorCode.INVALID_DATA)
    }

    data = data.map((item: any) => ({
      ...item,
      amountTopaid: item.amountUnpaid ?? 0,
      transactionId: id
    }));

    await prismaClient.transactionDetail.createMany(data);

    res.status(201).json({
      success: true,
      message: "Bulk request details created successfully",
    });

  };


export const bulkUpdate =
  async (req: Request, res: Response, next: NextFunction) => {

    const id = req.params.id;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

    // check if the user id is valid
    const user = await prismaClient.user.findUnique({
      where: { id: req.user?.id }
    });
    if (!user) throw new UnauthorizedException("Unauthorize ressource", ErrorCode.UNAUTHORIZE);

    let data = req.body;

    if (!Array.isArray(data) || data.length === 0) {
      throw new BadRequestException('Invalid params format', ErrorCode.INVALID_DATA)
    }

    // // Vérifier le format des mises à jour
    // for (const row of data) {
    //   if (!row.hasOwnProperty('_id') || typeof row._id !== 'string'
    //     || !row.hasOwnProperty('selected') || typeof row.selected !== 'boolean'
    //     || !row.hasOwnProperty('amountTopaid') || typeof row.amountTopaid !== 'number') {
    //     return res.status(400).json({ error: 'Invalid update format' });
    //   }
    // }
    // Data needed to be an array of objects
    // updateOne: {
    //   filter: { _id: row._id },
    //   update: {
    //     selected: row.selected,
    //     amountTopaid: row.amountTopaid,
    //   },
    // },

    await prismaClient.transactionDetail.createMany({
      data: data,
    });

    res.status(200).json({
      success: true,
      message: "successfully Bulk updated request details",
    });

  };


export const remove =
  async (req: Request, res: Response, next: NextFunction) => {

    const { id } = req.body;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

    const requestDetail = await prismaClient.transactionDetail.findUnique({
      where: { id: id },
    });
    if (!requestDetail) {
      throw new NotFoundException("Request not found", ErrorCode.RESSOURCE_NOT_FOUND);
    }
    await prismaClient.transactionDetail.delete({
      where: { id: id }
    });

    return res.status(200).json({
      success: true,
      message: "RequestDetail deleted successfully",
    });

  };


/*
 * create is an asynchronous function that creates a record in the database.
 * It first retrieves the user information from the database, and then creates records with the provided data,
 * including the payment date, the name of the user who created the record, and the user's ID.
 * If the user is not found, it returns an error with a 401 (Unauthorized) status code.
 */
export const create =
  async (req: Request, res: Response, next: NextFunction) => {

    const requestId = req.params.id;

    if (!requestId) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

    // check if the user id is valid
    const user = await prismaClient.user.findUnique({
      where: { id: req.user?.id }
    });
    if (!user) throw new UnauthorizedException("Unauthorize ressource", ErrorCode.UNAUTHORIZE);

    //TODO: check if the user is the assignee of the record

    const data = { ...req.body }

    const request = await prismaClient.transactionDetail.create({ data: data });

    res.status(201).json({
      success: true,
      data: request,
    });

  };

/*
 * update, is an asynchronous function
 * that update a speficic record with the provided information
 */
export const update =
  async (req: Request, res: Response, next: NextFunction) => {
    const requestId = req.params.id;

    // check if the provided ressource id is valid
    if (!requestId) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)


    // get the user information
    const user = await prismaClient.user.findUnique({
      where: { id: req.user?.id }
    });
    if (!user) throw new UnauthorizedException("Unauthorize ressource", ErrorCode.UNAUTHORIZE);

    // let data = {
    //   ...req.body,
    //   modifiedBy: user._id,
    // };
    // if (req.body.payment_date) {
    //   //TODO
    //   console.log("TODO fix issue in edit request feature")
    //   data = {
    //     ...data,
    //     payment_date: parseDMY(req.body.payment_date),
    //   };
    // }
    // // For validation
    // if (req.body.status === appConfig.status[3]) {
    //   data = {
    //     ...data,
    //     validator: user._id,
    //     validetedAt: new Date()
    //   };
    // }
    // // For Reject
    // if (req.body.status === appConfig.status[4]) {
    //   data = {
    //     ...data,
    //     validator: user._id,
    //     validetedAt: new Date(),
    //     refusal: true,
    //   };
    // }

    // const result = await requestModel.findByIdAndUpdate(
    //   requestId,
    //   { $set: data },
    //   { new: true }
    // );

    // // // Put into Redis for caching futur purpose
    // // await redis.set(
    // //   requestId,
    // //   JSON.stringify(result),
    // //   "EX",
    // //   appConfig.redis_session_expire
    // // );

    // return res.status(200).json({
    //   success: true,
    //   message: "Resource updated successfully",
    //   data: result,
    // });

  };

/*
 * softDelete, is an asynchronous function
 * that update a specicif record to a deleted status 
 * so simple user can not see them again
 */
export const softDelete =
  async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA);

    const data = await prismaClient.transactionDetail.findUnique({
      where: { id: id }
    });
    if (!data) throw new NotFoundException('Ressource not found', ErrorCode.INVALID_DATA);

    // get the user information
    const user = await prismaClient.user.findFirst({
      where: { id: req.user?.id },
    });
    if (!user) throw new UnauthorizedException("Unauthorize ressource", ErrorCode.UNAUTHORIZE);

    await prismaClient.transactionDetail.update({
      where: { id: id },
      data: {
        deleted: true,
        deletedAt: new Date(),
      }
    });
    await redis.del(id);

    return res.status(200).json({
      success: true,
      message: "Request soft deleted successfully",
    });

  };


//---------------------------------------------------------
//            SOFT BULK DELETE REQUEST
//---------------------------------------------------------
export const bulkSolftDelete =
  async (req: Request, res: Response, next: NextFunction) => {

    const { id } = req.params;
    if (!id) throw new BadRequestException('Invalid params', ErrorCode.INVALID_DATA)

    const request = await prismaClient.transactionDetail.findUnique({
      where: { id: id },
    });
    if (!request) throw new NotFoundException("Request not found", ErrorCode.RESSOURCE_NOT_FOUND);

    await prismaClient.transactionDetail.delete({
      where: { id: id }
    });
    await redis.del(id);

    return res.status(200).json({
      success: true,
      message: "Request deleted successfully",
    });

  };
