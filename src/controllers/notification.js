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
exports.updateNotification = exports.getAllNotifications = void 0;
const node_cron_1 = __importDefault(require("node-cron"));
const prismadb_1 = __importDefault(require("../libs/prismadb"));
const not_found_1 = __importDefault(require("../exceptions/not-found"));
const http_exception_1 = require("../exceptions/http-exception");
//---------------------------------------------------------
//              get all notifications -- only for admin
//---------------------------------------------------------
const getAllNotifications = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const notifications = yield prismadb_1.default.internalNotification.findMany({ where: { createdAt: "desc" } });
    res.status(200).json({
        success: true,
        notifications,
    });
});
exports.getAllNotifications = getAllNotifications;
//-----------------------------------------------
//              update notifications status
//-----------------------------------------------
const updateNotification = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const notification = yield prismadb_1.default.internalNotification.findUnique({
        where: { id: req.params.id }
    });
    if (!notification)
        throw new not_found_1.default("Notification not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    if (notification.status) {
        notification.status = "read";
        yield prismadb_1.default.internalNotification.update({
            where: { id: req.params.id },
            data: { status: notification.status }
        });
    }
    const notifications = yield prismadb_1.default
        .internalNotification
        .findMany({ where: { createdAt: "desc" } });
    res.status(201).json({
        success: true,
        notifications,
    });
});
exports.updateNotification = updateNotification;
//-----------------------------------------------
//              delete notifications -- only for admin
//-----------------------------------------------
node_cron_1.default.schedule('0 0 0 * * *', () => __awaiter(void 0, void 0, void 0, function* () {
    const thirtyDayAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    yield prismadb_1.default.internalNotification.deleteMany({
        where: {
            status: "read",
            createdAt: { lt: thirtyDayAgo }
        }
    });
    console.log('----------------------------');
    console.log('Delete read notifications');
    console.log('----------------------------');
}));
