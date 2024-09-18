"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.expiredFormatD = exports.expiredFormat = exports.sendToken = exports.refreshTokenOptions = exports.accessTokenOptions = void 0;
const redis_1 = require("./redis");
const secrets_1 = require("../../secrets");
//parse environnement variables to integrate with fallback values
const accessTokenExpire = parseInt(secrets_1.ACCESS_TOKEN_EXPIRE, 10);
const refreshTokenExpire = parseInt(secrets_1.REFRESH_TOKEN_EXPIRE, 10);
// Options for cookies 
// The is a issue with timezone we add 1h (3600) from universal time
exports.accessTokenOptions = {
    expires: new Date(Date.now() + (3600 + accessTokenExpire) * 1000),
    maxAge: (3600 + accessTokenExpire) * 1000,
    httpOnly: true,
    sameSite: 'lax',
};
exports.refreshTokenOptions = {
    expires: new Date(Date.now() + (3600 + refreshTokenExpire) * 1000),
    maxAge: (3600 + refreshTokenExpire) * 1000,
    httpOnly: true,
    sameSite: 'lax',
};
//TODO update User type  ==> user:IUser
const sendToken = (user, statusCode, res) => {
    const accessToken = user.signAccessToken();
    const refreshToken = user.signRefreshToken();
    //Upload session to redis
    redis_1.redis.set(user.id, JSON.stringify(user), "EX", secrets_1.REFRESH_TOKEN_EXPIRE);
    // Only set secure to true in production
    if (process.env.NODE_ENV === 'production') {
        exports.accessTokenOptions.secure = true;
    }
    res.cookie("access_token", accessToken, exports.accessTokenOptions);
    res.cookie("refresh_token", refreshToken, exports.refreshTokenOptions);
    res.status(statusCode).json({
        success: true,
        user: user.cleanUser(),
        accessToken,
        refreshToken
    });
};
exports.sendToken = sendToken;
const expiredFormat = (token_expire_in_second) => {
    const expire = Math.floor(parseInt(token_expire_in_second) / 60);
    return `${expire}m`;
};
exports.expiredFormat = expiredFormat;
const expiredFormatD = (token_expire_in_day) => {
    return `${token_expire_in_day}d`;
};
exports.expiredFormatD = expiredFormatD;
