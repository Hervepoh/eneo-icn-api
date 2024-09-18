class HttpException extends Error {
    message: string;
    statusCode: Number;
    errors: any;
    errorCode: ErrorCode;

    constructor(
        message:any,
        statusCode:Number,
        errorCode:ErrorCode,
        errors:any,
    ){
        super(message);
        this.message = message;
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.errors = errors;
        
        Error.captureStackTrace(this,this.constructor)
    }

}

export default HttpException;

export enum ErrorCode {
    USER_NOT_FOUND = 4040,
    RESSOURCE_NOT_FOUND = 4040,
    RESSOURCE_ALREADY_EXISTS = 4001,
    INCORRECT_PASSWORD = 4002,
    UNFULLFIELD_REQUIRED_FIELD = 4003,
    INVALID_DATA = 4005,
    UNPROCCESSABLE_ENTITY = 4220,
    UNAUTHORIZE = 4010,
    INTERNAL_EXCEPTION = 5001,
    BAD_CONFIGURATION = 5005,
   
}