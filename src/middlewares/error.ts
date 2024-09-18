import { NextFunction, Request, Response } from "express";
import HttpException, { ErrorCode } from "../exceptions/http-exception";


export const ErrorMiddleware = (
    err: any,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    err.statusCode = err.statusCode || 500;
    err.message = err.message || 'Internal Server Error';

    // Wrong mongodb Id error
    if (err.name === "CastError") {
        const message = `Ressource not found, Invalid: ${err.path}`
        err = new HttpException(message, 404 , ErrorCode.USER_NOT_FOUND , null);
    }


    // Wrong JWT error
    if (err.code === "JsonWebTokenError") {
        const message = `Json Web Token is invalid , Try again`
        err = new HttpException(message, 400, ErrorCode.USER_NOT_FOUND , null);
    }

    // Expire JWT error
    if (err.code === "TokenExpiredError") {
        const message = `Json Web Token is expired , Try again`
        err = new HttpException(message, 400,ErrorCode.USER_NOT_FOUND , null);
    }

    res.status(err.statusCode).json({
        success: false,
        message: err.message,
        errorCode: err.errorCode,
        errors: err.errors
    })

}