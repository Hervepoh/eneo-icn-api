"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redisConfig = redisConfig;
const secrets_1 = require("../secrets");
function redisConfig() {
    return {
        host: secrets_1.REDIS_HOSTNAME,
        port: parseInt(secrets_1.REDIS_PORT || "6379"),
        password: secrets_1.REDIS_PASSWORD
    };
}
