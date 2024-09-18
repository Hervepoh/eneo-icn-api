import { Router } from "express";

import { serviceType } from "../constants/enum";
import { errorHandler } from "../error-handler";
import { getAllNotifications, updateNotification } from "../controllers/notification";
import authMiddleware, { authorizeMiddleware } from "../middlewares/auth";

const serviceName = serviceType.NOTIFICATION;
const notificationRoutes: Router = Router();

notificationRoutes.get('/', [authMiddleware, authorizeMiddleware(`${serviceName}-READ`)], errorHandler(getAllNotifications));
notificationRoutes.put('/:id', [authMiddleware, authorizeMiddleware(`${serviceName}-WRITE`)], errorHandler(updateNotification));

export default notificationRoutes;