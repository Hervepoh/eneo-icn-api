import { Router } from "express";

import { errorHandler } from "../error-handler";
import { create, get, getUserNotification } from "../controllers/user";

const userRoutes:Router = Router();

userRoutes.post('/', errorHandler(create));
userRoutes.get('/', errorHandler(get));
userRoutes.get('/notifications', errorHandler(getUserNotification));

export default userRoutes;