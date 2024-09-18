import { Router } from "express";

import { serviceType } from "../constants/enum";
import { errorHandler } from "../error-handler";
import authMiddleware, { authorizeMiddleware } from "../middlewares/auth";
import {
    getICNNextCode,
    getICNDematerializeCode,
    getICNGroupes,
    getICN,
    generationOfIntegrationFile
} from "../controllers/icn";

const serviceName = serviceType.ICN;
const interncreditRoutes:Router = Router();

interncreditRoutes.get('/next-code', [authMiddleware,authorizeMiddleware(`${serviceName}-NEXTCODE`)] , errorHandler(getICNNextCode));
interncreditRoutes.get('/next-dematerialization', [authMiddleware,authorizeMiddleware(`${serviceName}-NEXTDEMATERIALIZATION`)] ,errorHandler(getICNDematerializeCode));
interncreditRoutes.get('/groupes', [authMiddleware,authorizeMiddleware(`${serviceName}-GROUPES`)] , errorHandler(getICNGroupes));
interncreditRoutes.get('/', [authMiddleware,authorizeMiddleware(`${serviceName}-GET`)], errorHandler(getICN));
interncreditRoutes.get('/documents', [authMiddleware,authorizeMiddleware(`${serviceName}-DOCUMENTS`)] , errorHandler(generationOfIntegrationFile));

export default interncreditRoutes;