"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_exception_1 = __importDefault(require("./http-exception"));
class NotFoundException extends http_exception_1.default {
    constructor(message, errorCode) {
        super(message, 404, errorCode, null);
    }
}
exports.default = NotFoundException;
