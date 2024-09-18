"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const error_handler_1 = require("../error-handler");
const auth_1 = __importDefault(require("../middlewares/auth"));
const auth_2 = require("../controllers/auth");
const authRoutes = (0, express_1.Router)();
authRoutes.post('/register', (0, error_handler_1.errorHandler)(auth_2.signup));
authRoutes.post('/activation', (0, error_handler_1.errorHandler)(auth_2.activate));
authRoutes.post('/login', (0, error_handler_1.errorHandler)(auth_2.signin));
authRoutes.post('/logout', [auth_1.default], (0, error_handler_1.errorHandler)(auth_2.signout));
authRoutes.get('/me', [auth_1.default], (0, error_handler_1.errorHandler)(auth_2.me));
authRoutes.get('/refresh', [auth_1.default], (0, error_handler_1.errorHandler)(auth_2.updateAccessToken));
exports.default = authRoutes;
