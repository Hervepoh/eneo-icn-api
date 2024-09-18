import HttpException, { ErrorCode } from "./http-exception";

export default class ConfigurationException extends HttpException {
    constructor(
        message:string,
        errorCode:ErrorCode,
        errors?: any
    ){
        super(message,500, errorCode,errors);
    }

}
