"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.acceptablePasswordPolicy = exports.passwordPolicy = exports.isValidUUID = exports.isAnAcceptablePassword = exports.isValidPassword = exports.isValidEmail = void 0;
const emailRegexPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegexPattern = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,}$/;
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const acceptablePasswordRegexPattern = /.{6,}/;
const isValidEmail = (value) => {
    return emailRegexPattern.test(value);
};
exports.isValidEmail = isValidEmail;
const isValidPassword = (value) => {
    return passwordRegexPattern.test(value);
};
exports.isValidPassword = isValidPassword;
const isAnAcceptablePassword = (value) => {
    return acceptablePasswordRegexPattern.test(value);
};
exports.isAnAcceptablePassword = isAnAcceptablePassword;
const isValidUUID = (id) => {
    return uuidRegex.test(id);
};
exports.isValidUUID = isValidUUID;
exports.passwordPolicy = `Password must contain at least one lower-letter, at least one Upper-letter,at least one digit, at least one special caracter {#?!@$%^&*-}`;
exports.acceptablePasswordPolicy = `Password must contain at leastt six (6) characters`;
