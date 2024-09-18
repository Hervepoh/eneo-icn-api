import { Router } from "express";

import { serviceType } from "../constants/enum";
import { errorHandler } from "../error-handler";
import { assignPermission, bulkCreate, bulkRemove, create, get, getById, getPermissions, remove, update } from "../controllers/role";
import authMiddleware, { authorizeMiddleware } from "../middlewares/auth";

const serviceName = serviceType.ROLE;
const roleRoutes: Router = Router();

roleRoutes.post('/', [authMiddleware, authorizeMiddleware(`${serviceName}-CREATE`)], errorHandler(create));
roleRoutes.get('/', [authMiddleware, authorizeMiddleware(`${serviceName}-READ`)], errorHandler(get));
roleRoutes.get('/:id', [authMiddleware, authorizeMiddleware(`${serviceName}-READ`)], errorHandler(getById));
roleRoutes.put('/:id', [authMiddleware,authorizeMiddleware(`${serviceName}-UPDATE`)], errorHandler(update));
roleRoutes.delete('/:id', [authMiddleware,authorizeMiddleware(`${serviceName}-DELETE`)], errorHandler(remove));
roleRoutes.get('/:id/permission',[authMiddleware,authorizeMiddleware(`${serviceName}-PERMISSION-READ`)] , errorHandler(assignPermission));
roleRoutes.post('/:id/permission',[authMiddleware,authorizeMiddleware(`${serviceName}-PERMISSION-WRITE`)] , errorHandler(getPermissions));

roleRoutes.post('/bulk',[authMiddleware,authorizeMiddleware(`${serviceName}-BULKCREATE`)] , errorHandler(bulkCreate));
roleRoutes.delete('/bulk', [authMiddleware,authorizeMiddleware(`${serviceName}-BULKDELETE`)], errorHandler(bulkRemove));




export default roleRoutes;