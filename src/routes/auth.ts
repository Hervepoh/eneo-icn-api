import { Router } from "express";

import { errorHandler } from "../error-handler";
import authMiddleware from "../middlewares/auth";
import { signup, signin, me, activate, signout, updateAccessToken } from "../controllers/auth";


const authRoutes: Router = Router();

authRoutes.post('/register', errorHandler(signup));
authRoutes.post('/activation', errorHandler(activate));
authRoutes.post('/login', errorHandler(signin));
authRoutes.post('/logout',  [authMiddleware] , errorHandler(signout));
authRoutes.get('/me', [authMiddleware], errorHandler(me));
authRoutes.get('/refresh', [authMiddleware], errorHandler(updateAccessToken));

export default authRoutes;