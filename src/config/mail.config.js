"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mailConfig = void 0;
const secrets_1 = require("../secrets");
exports.mailConfig = {
    service: secrets_1.SMTP_SERVICE || 'smtp-mail.outlook.com',
    host: secrets_1.SMTP_HOST || '',
    port: secrets_1.SMTP_PORT || "587",
    tls: {
        ciphers: secrets_1.SMTP_CIPHERS || "SSLv3",
        rejectUnauthorized: false,
    },
    auth: {
        user: secrets_1.SMTP_MAIL || '',
        pass: secrets_1.SMTP_PASSWORD || '',
    }
};
