"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_exception_1 = __importDefault(require("./http-exception"));
class ConfigurationException extends http_exception_1.default {
    constructor(message, errorCode, errors) {
        super(message, 500, errorCode, errors);
    }
}
exports.default = ConfigurationException;
