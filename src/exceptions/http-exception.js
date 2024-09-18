"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ErrorCode = void 0;
class HttpException extends Error {
    constructor(message, statusCode, errorCode, errors) {
        super(message);
        this.message = message;
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.errors = errors;
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.default = HttpException;
var ErrorCode;
(function (ErrorCode) {
    ErrorCode[ErrorCode["USER_NOT_FOUND"] = 4040] = "USER_NOT_FOUND";
    ErrorCode[ErrorCode["RESSOURCE_NOT_FOUND"] = 4040] = "RESSOURCE_NOT_FOUND";
    ErrorCode[ErrorCode["RESSOURCE_ALREADY_EXISTS"] = 4001] = "RESSOURCE_ALREADY_EXISTS";
    ErrorCode[ErrorCode["INCORRECT_PASSWORD"] = 4002] = "INCORRECT_PASSWORD";
    ErrorCode[ErrorCode["UNFULLFIELD_REQUIRED_FIELD"] = 4003] = "UNFULLFIELD_REQUIRED_FIELD";
    ErrorCode[ErrorCode["INVALID_DATA"] = 4005] = "INVALID_DATA";
    ErrorCode[ErrorCode["UNPROCCESSABLE_ENTITY"] = 4220] = "UNPROCCESSABLE_ENTITY";
    ErrorCode[ErrorCode["UNAUTHORIZE"] = 4010] = "UNAUTHORIZE";
    ErrorCode[ErrorCode["INTERNAL_EXCEPTION"] = 5001] = "INTERNAL_EXCEPTION";
    ErrorCode[ErrorCode["BAD_CONFIGURATION"] = 5005] = "BAD_CONFIGURATION";
})(ErrorCode || (exports.ErrorCode = ErrorCode = {}));
