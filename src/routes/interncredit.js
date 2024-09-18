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
const icn_1 = require("../controllers/icn");
const serviceName = enum_1.serviceType.ICN;
const interncreditRoutes = (0, express_1.Router)();
interncreditRoutes.get('/next-code', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-NEXTCODE`)], (0, error_handler_1.errorHandler)(icn_1.getICNNextCode));
interncreditRoutes.get('/next-dematerialization', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-NEXTDEMATERIALIZATION`)], (0, error_handler_1.errorHandler)(icn_1.getICNDematerializeCode));
interncreditRoutes.get('/groupes', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-GROUPES`)], (0, error_handler_1.errorHandler)(icn_1.getICNGroupes));
interncreditRoutes.get('/', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-GET`)], (0, error_handler_1.errorHandler)(icn_1.getICN));
interncreditRoutes.get('/documents', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-DOCUMENTS`)], (0, error_handler_1.errorHandler)(icn_1.generationOfIntegrationFile));
exports.default = interncreditRoutes;
