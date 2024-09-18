import HttpException, { ErrorCode } from "./http-exception";

export default class NotFoundException extends HttpException {
    constructor(
        message:any,
        errorCode:ErrorCode,
    ){
        super(message,404, errorCode,null);
    }

}
