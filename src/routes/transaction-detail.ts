import { Router } from "express";

import { serviceType } from "../constants/enum";
import { errorHandler } from "../error-handler";
import authMiddleware, { authorizeMiddleware } from "../middlewares/auth";
import { create, get, update , remove, bulkCreate, bulkUpdate  } from "../controllers/transaction-details";

const serviceName = serviceType.TRANSACTION;
const transactionDetailRoutes:Router = Router();

transactionDetailRoutes.post('/',  [authMiddleware,authorizeMiddleware(`${serviceName}-CREATE`)] , errorHandler(create));
transactionDetailRoutes.get('/', [authMiddleware,authorizeMiddleware(`${serviceName}-READ`)] ,errorHandler(get));
transactionDetailRoutes.put('/:id', [authMiddleware,authorizeMiddleware(`${serviceName}-UPDATE`)], errorHandler(update));
transactionDetailRoutes.delete('/:id', [authMiddleware,authorizeMiddleware(`${serviceName}-DELETE`)] , errorHandler(remove));

transactionDetailRoutes.post('/bulk',[authMiddleware,authorizeMiddleware(`${serviceName}-BULKCREATE`)] , errorHandler(bulkCreate));
transactionDetailRoutes.put('/bulk', [authMiddleware,authorizeMiddleware(`${serviceName}-BULKDELETE`)], errorHandler(bulkUpdate));


export default transactionDetailRoutes;