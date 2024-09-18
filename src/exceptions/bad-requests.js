"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_exception_1 = __importDefault(require("./http-exception"));
class BadRequestException extends http_exception_1.default {
    constructor(message, errorCode) {
        super(message, 400, errorCode, null);
    }
}
exports.default = BadRequestException;
