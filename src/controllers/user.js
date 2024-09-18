"use strict";
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
exports.getUserNotification = exports.get = exports.create = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const redis_1 = require("../libs/utils/redis");
const prismadb_1 = __importDefault(require("../libs/prismadb"));
const bad_requests_1 = __importDefault(require("../exceptions/bad-requests"));
const http_exception_1 = require("../exceptions/http-exception");
const validator_1 = require("../libs/utils/validator");
const secrets_1 = require("../secrets");
const users_1 = require("../schema/users");
const client_1 = require("@prisma/client");
const key = 'users';
const create = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input
    users_1.signUpSchema.parse(req.body);
    const { name, email, password, avatar, role } = req.body;
    if (!(0, validator_1.isAnAcceptablePassword)(password)) {
        throw new bad_requests_1.default(`Invalid Password : ${validator_1.acceptablePasswordPolicy}`, http_exception_1.ErrorCode.INVALID_DATA);
    }
    // Create user
    let user = yield prismadb_1.default.user.create({
        data: {
            name,
            email,
            password: yield bcrypt_1.default.hash(password, parseInt(secrets_1.SALT_ROUNDS || '10')),
        }
    });
    // User notification by mail
    yield prismadb_1.default.notification.create({
        data: {
            email: user.email,
            message: `Here are your credentials: **Email**: ${user.email}  **Temporary Password**: ${password}`,
            method: client_1.NotificationMethod.EMAIL,
            subject: "Your account has been created successfully.",
            template: "new.mail.ejs",
        },
    });
    res.status(201).json({
        success: true,
        data: user
    });
});
exports.create = create;
//-----------------------------------------------
//       Get All Users  -- only for admin users
//-----------------------------------------------
const get = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const usersJSON = yield redis_1.redis.get("allusers");
    if (usersJSON) {
        const users = JSON.parse(usersJSON);
        res.status(200).json({
            success: true,
            users,
        });
    }
    else {
        const users = yield prismadb_1.default.user.findMany({
            where: { createdAt: 'desc' }
        });
        yield redis_1.redis.set(key, JSON.stringify(users));
        res.status(200).json({
            success: true,
            users,
        });
    }
});
exports.get = get;
//-----------------------------------------------
//              get user notifications
//-----------------------------------------------
const getUserNotification = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const notifications = yield prismadb_1.default.internalNotification
        .findMany({ where: { createdAt: "desc" } });
    res.status(200).json({
        success: true,
        notifications,
    });
});
exports.getUserNotification = getUserNotification;
