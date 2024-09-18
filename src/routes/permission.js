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
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const enum_1 = require("../constants/enum");
const error_handler_1 = require("../error-handler");
const auth_1 = __importStar(require("../middlewares/auth"));
const permission_1 = require("../controllers/permission");
const serviceName = enum_1.serviceType.PERMISSION;
const permissionRoutes = (0, express_1.Router)();
permissionRoutes.post('/', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-CREATE`)], (0, error_handler_1.errorHandler)(permission_1.create));
permissionRoutes.get('/', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-READ`)], (0, error_handler_1.errorHandler)(permission_1.get));
permissionRoutes.get('/:id', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-READ`)], (0, error_handler_1.errorHandler)(permission_1.getById));
permissionRoutes.put('/:id', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-UPDATE`)], (0, error_handler_1.errorHandler)(permission_1.update));
permissionRoutes.delete('/:id', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-DELETE`)], (0, error_handler_1.errorHandler)(permission_1.remove));
permissionRoutes.post('/bulk', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-BULKCREATE`)], (0, error_handler_1.errorHandler)(permission_1.bulkCreate));
permissionRoutes.delete('/bulk', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-BULKDELETE`)], (0, error_handler_1.errorHandler)(permission_1.bulkRemove));
exports.default = permissionRoutes;
