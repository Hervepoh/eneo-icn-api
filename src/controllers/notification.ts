import { NextFunction, Request, Response } from "express";
import ejs from "ejs";
import path from "path";
import cron from "node-cron";

import sendMail from "../libs/utils/sendMail";
import prismaClient from "../libs/prismadb";
import NotFoundException from "../exceptions/not-found";
import { ErrorCode } from "../exceptions/http-exception";

//---------------------------------------------------------
//              get all notifications -- only for admin
//---------------------------------------------------------
export const getAllNotifications =
  async (req: Request, res: Response, next: NextFunction) => {

    const notifications = await prismaClient.internalNotification.findMany(
      { where: { createdAt: "desc" } }
    )

    res.status(200).json({
      success: true,
      notifications,
    });
  };


//-----------------------------------------------
//              update notifications status
//-----------------------------------------------
export const updateNotification =
  async (req: Request, res: Response, next: NextFunction) => {
    const notification = await prismaClient.internalNotification.findUnique({
      where: { id: req.params.id }
    });

    if (!notification) throw new NotFoundException("Notification not found", ErrorCode.RESSOURCE_NOT_FOUND);

    if (notification.status) {
      notification.status = "read";
      await prismaClient.internalNotification.update({
        where: { id: req.params.id },
        data: { status: notification.status }
      });
    }

    const notifications = await prismaClient
      .internalNotification
      .findMany({ where: { createdAt: "desc" } });

    res.status(201).json({
      success: true,
      notifications,
    });
  };

//-----------------------------------------------
//              delete notifications -- only for admin
//-----------------------------------------------
cron.schedule('0 0 0 * * *', async () => {
  const thirtyDayAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  await prismaClient.internalNotification.deleteMany({
    where: {
      status: "read", 
      createdAt: { lt: thirtyDayAgo }
    }
  });
  console.log('----------------------------');
  console.log('Delete read notifications');
  console.log('----------------------------');
});