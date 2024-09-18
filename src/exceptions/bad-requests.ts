import HttpException, { ErrorCode } from "./http-exception";

export default class BadRequestException extends HttpException {
    constructor(
        message:any,
        errorCode:ErrorCode,
    ){
        super(message,400, errorCode,null);
    }

}
