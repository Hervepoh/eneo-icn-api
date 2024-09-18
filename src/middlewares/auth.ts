import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

import { redis } from "../libs/utils/redis";
import UnauthorizedException from "../exceptions/unauthorized";
import HttpException, { ErrorCode } from "../exceptions/http-exception";
import { CatchAsyncError } from "./catchAsyncErrors";
import { ACCESS_TOKEN_SECRET } from "../secrets";
import prismaClient from "../libs/prismadb";
import { User } from "@prisma/client";

// Extend the Request interface
declare module 'express' {
    interface Request {
        user?: User & { role?: any } & { roles?: any[] };
    }
}


// Authenticated User
const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    // 1. extract the token from the headers
    const access_token = req.cookies.access_token;
    //const access_token = req.headers.authorization;
    if (!access_token) {
        return next(new UnauthorizedException("Unauthorized: Please login to access this ressource", ErrorCode.UNAUTHORIZE))
    }
    // 2. if token is not present , throw an error of unauthorized access
    try {
        // 3. if token is present, verify that token is valid and extract the payload
        const payload = jwt.verify(access_token, ACCESS_TOKEN_SECRET as string) as JwtPayload;
        if (!payload) {
            return next(new UnauthorizedException("Unauthorized: Access token is not valid, please login to access this resource", ErrorCode.UNAUTHORIZE))
        }
        // 4. Get the redis user from the payload
        const user = await redis.get(payload.id);
        if (!user) {
            // Check if user is in the database
            const userDB = await prismaClient.user.findFirst({
                where: { id: payload.id },
                include: { roles: true }, // Include roles relation
            });
            if (!userDB) {
                return next(new UnauthorizedException("Unauthorized: Please login to access this resource", ErrorCode.UNAUTHORIZE));
            }
            // 5. Attach the user to the current request object
            req.user = userDB;
            // TOTO: set userBD in redis to avoid to fetch again the database
        } else {
            // 5. Attach the user to the current request object
            req.user = JSON.parse(user); // Parse the user from Redis
        }

        next();

    } catch (error) {
        next(new UnauthorizedException("Unauthorized: Please login to access this ressource", ErrorCode.UNAUTHORIZE))
    }


};


// Administrator User
export const adminMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const user = req.user
    if (user?.role == 'ADMIN') {
        next()
    }
    else {
        next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZE))
    }


}

// Validate User Role/Permissions
export const authorizeMiddleware = (...allowedPermissions: string[]) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        const userRoles = req.user?.roles || []; // Assuming roles is an array

        if (!userRoles.length) {
            return next(new HttpException(`Forbidden: No roles assigned to the user`, 403, ErrorCode.UNAUTHORIZE, null));
        }

        // Fetch permissions for the user's roles
        // Récupérer les permissions pour les rôles de l'utilisateur
        const permissions = await Promise.all(userRoles.map(role =>
            prismaClient.rolePermission.findMany({
                where: { roleId: role.id }, // Utilisation de role.id pour la recherche
                include: {
                    permission: true // Inclure les permissions associées
                },
            })
        ));

        // Aplatir les permissions et vérifier contre les permissions autorisées
        const userPermissions = permissions.flatMap(rolePermissions =>
            rolePermissions.map(rp => rp.permission.name)
        );

        const hasPermission = userPermissions.some(permission => allowedPermissions.includes(permission));
        if (!hasPermission) {
            return next(new HttpException(`Forbidden: You do not have permission to access this resource`, 403, ErrorCode.UNAUTHORIZE, null));
        }


        next();
    }
}

export default authMiddleware;
