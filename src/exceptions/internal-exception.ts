import HttpException, { ErrorCode } from "./http-exception";

export default class InternalException extends HttpException {
    constructor(
        message:any,
        errors:any,
        errorCode:ErrorCode,     
    ){
        super(message, 500, errorCode , errors);
    }

}

