"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authorizeMiddleware = exports.adminMiddleware = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const redis_1 = require("../libs/utils/redis");
const unauthorized_1 = __importDefault(require("../exceptions/unauthorized"));
const http_exception_1 = __importStar(require("../exceptions/http-exception"));
const secrets_1 = require("../secrets");
const prismadb_1 = __importDefault(require("../libs/prismadb"));
// Authenticated User
const authMiddleware = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // 1. extract the token from the headers
    const access_token = req.cookies.access_token;
    //const access_token = req.headers.authorization;
    if (!access_token) {
        return next(new unauthorized_1.default("Unauthorized: Please login to access this ressource", http_exception_1.ErrorCode.UNAUTHORIZE));
    }
    // 2. if token is not present , throw an error of unauthorized access
    try {
        // 3. if token is present, verify that token is valid and extract the payload
        const payload = jsonwebtoken_1.default.verify(access_token, secrets_1.ACCESS_TOKEN_SECRET);
        if (!payload) {
            return next(new unauthorized_1.default("Unauthorized: Access token is not valid, please login to access this resource", http_exception_1.ErrorCode.UNAUTHORIZE));
        }
        // 4. Get the redis user from the payload
        const user = yield redis_1.redis.get(payload.id);
        if (!user) {
            // Check if user is in the database
            const userDB = yield prismadb_1.default.user.findFirst({
                where: { id: payload.id },
                include: { roles: true }, // Include roles relation
            });
            if (!userDB) {
                return next(new unauthorized_1.default("Unauthorized: Please login to access this resource", http_exception_1.ErrorCode.UNAUTHORIZE));
            }
            // 5. Attach the user to the current request object
            req.user = userDB;
            // TOTO: set userBD in redis to avoid to fetch again the database
        }
        else {
            // 5. Attach the user to the current request object
            req.user = JSON.parse(user); // Parse the user from Redis
        }
        next();
    }
    catch (error) {
        next(new unauthorized_1.default("Unauthorized: Please login to access this ressource", http_exception_1.ErrorCode.UNAUTHORIZE));
    }
});
// Administrator User
const adminMiddleware = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const user = req.user;
    if ((user === null || user === void 0 ? void 0 : user.role) == 'ADMIN') {
        next();
    }
    else {
        next(new unauthorized_1.default('Unauthorized', http_exception_1.ErrorCode.UNAUTHORIZE));
    }
});
exports.adminMiddleware = adminMiddleware;
// Validate User Role/Permissions
const authorizeMiddleware = (...allowedPermissions) => {
    return (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const userRoles = ((_a = req.user) === null || _a === void 0 ? void 0 : _a.roles) || []; // Assuming roles is an array
        if (!userRoles.length) {
            return next(new http_exception_1.default(`Forbidden: No roles assigned to the user`, 403, http_exception_1.ErrorCode.UNAUTHORIZE, null));
        }
        // Fetch permissions for the user's roles
        // Récupérer les permissions pour les rôles de l'utilisateur
        const permissions = yield Promise.all(userRoles.map(role => prismadb_1.default.rolePermission.findMany({
            where: { roleId: role.id }, // Utilisation de role.id pour la recherche
            include: {
                permission: true // Inclure les permissions associées
            },
        })));
        // Aplatir les permissions et vérifier contre les permissions autorisées
        const userPermissions = permissions.flatMap(rolePermissions => rolePermissions.map(rp => rp.permission.name));
        const hasPermission = userPermissions.some(permission => allowedPermissions.includes(permission));
        if (!hasPermission) {
            return next(new http_exception_1.default(`Forbidden: You do not have permission to access this resource`, 403, http_exception_1.ErrorCode.UNAUTHORIZE, null));
        }
        next();
    });
};
exports.authorizeMiddleware = authorizeMiddleware;
exports.default = authMiddleware;
