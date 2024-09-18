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
exports.ErrorMiddleware = void 0;
const http_exception_1 = __importStar(require("../exceptions/http-exception"));
const ErrorMiddleware = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.message = err.message || 'Internal Server Error';
    // Wrong mongodb Id error
    if (err.name === "CastError") {
        const message = `Ressource not found, Invalid: ${err.path}`;
        err = new http_exception_1.default(message, 404, http_exception_1.ErrorCode.USER_NOT_FOUND, null);
    }
    // Wrong JWT error
    if (err.code === "JsonWebTokenError") {
        const message = `Json Web Token is invalid , Try again`;
        err = new http_exception_1.default(message, 400, http_exception_1.ErrorCode.USER_NOT_FOUND, null);
    }
    // Expire JWT error
    if (err.code === "TokenExpiredError") {
        const message = `Json Web Token is expired , Try again`;
        err = new http_exception_1.default(message, 400, http_exception_1.ErrorCode.USER_NOT_FOUND, null);
    }
    res.status(err.statusCode).json({
        success: false,
        message: err.message,
        errorCode: err.errorCode,
        errors: err.errors
    });
};
exports.ErrorMiddleware = ErrorMiddleware;
