import HttpException, { ErrorCode } from "./http-exception";

export default class UnprocessableException extends HttpException {
    constructor(
        error: any,
        message:any,
        errorCode:ErrorCode,
    ){
        super(message,422, errorCode,error);
    }

}
