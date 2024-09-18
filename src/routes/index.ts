import { Router } from "express";
import authRoutes from "./auth";
import userRoutes from "./user";
import roleRoutes from "./role";
import bankRoutes from "./bank";
import permissionRoutes from "./permission";
import paymentModeRoutes from "./paymentMode";
import interncreditRoutes from "./interncredit";
import unpaidRoutes from "./unpaid";
import transactionRoutes from "./transaction";
import transactionDetailRoutes from "./transaction-detail";
import summaryRoutes from "./summary";

const rootRouter:Router = Router();

rootRouter.use('/auth' , authRoutes);
rootRouter.use('/users' , userRoutes);
rootRouter.use('/roles' , roleRoutes);
rootRouter.use('/permissions' , permissionRoutes);

rootRouter.use('/summary' , summaryRoutes);
rootRouter.use('/banks' , bankRoutes);
rootRouter.use('/pay-modes' , paymentModeRoutes);
rootRouter.use('/requests' , transactionRoutes);
rootRouter.use('/requests-details' , transactionDetailRoutes);
rootRouter.use('/search-unpaid' , unpaidRoutes);
rootRouter.use('/icn' , interncreditRoutes);

export default rootRouter;