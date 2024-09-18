import HttpException, { ErrorCode } from "./http-exception";

export default class UnauthorizedException extends HttpException {
    constructor(
        message:string,
        errorCode:ErrorCode,
        errors?: any
    ){
        super(message,401, errorCode,errors);
    }

}
