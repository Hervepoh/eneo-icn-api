import { Router } from "express";

import { errorHandler } from "../error-handler";
import { create } from "../controllers/user";

const userRoutes:Router = Router();

userRoutes.post('/', errorHandler(create));

export default userRoutes;