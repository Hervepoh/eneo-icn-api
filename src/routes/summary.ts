import { Router } from "express";

import { serviceType } from "../constants/enum";
import { errorHandler } from "../error-handler";
import authMiddleware, { authorizeMiddleware } from "../middlewares/auth";
import { all, me } from "../controllers/summary";

const serviceName = serviceType.SUMMARY;
const summaryRoutes:Router = Router();

summaryRoutes.get('/', [authMiddleware,authorizeMiddleware(`${serviceName}-READ`)] , errorHandler(all));
summaryRoutes.get('/me', [authMiddleware,authorizeMiddleware(`${serviceName}-READ`)] ,errorHandler(me));

export default summaryRoutes;