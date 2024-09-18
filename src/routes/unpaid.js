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
const error_handler_1 = require("../error-handler");
const auth_1 = __importStar(require("../middlewares/auth"));
const unpaid_1 = require("../controllers/unpaid");
const enum_1 = require("../constants/enum");
const serviceName = enum_1.serviceType.UNPAID;
const unpaidRoutes = (0, express_1.Router)();
unpaidRoutes.get('/', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBills));
unpaidRoutes.get('/by-contractNumber', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBillsByContractNumber));
unpaidRoutes.get('/by-invoiceNumber', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBillsByInvoiceNumber));
unpaidRoutes.get('/by-customerRegroupNumber', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBillsByCustomerRegroupNumber));
unpaidRoutes.get('/by-customerName', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBillsByCustomerName));
unpaidRoutes.get('/onList', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBillsOnList));
unpaidRoutes.get('/onListWithAccount', [auth_1.default, (0, auth_1.authorizeMiddleware)(`${serviceName}-SEARCH`)], (0, error_handler_1.errorHandler)(unpaid_1.getUnpaidBillsOnListWithAccount));
exports.default = unpaidRoutes;
