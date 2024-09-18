"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserEntity = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const secrets_1 = require("../secrets");
const jwt_1 = require("../libs/utils/jwt");
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
class UserEntity {
    constructor(user) {
        this.id = user.id;
        this.name = user.name;
        this.email = user.email;
        this.password = user.password;
        this.avatar = user.avatar;
        this.roles = user.roles;
        this.role = user.role;
    }
    comparePassword(inputPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield bcrypt_1.default.compare(inputPassword, this.password);
        });
    }
    signAccessToken() {
        return jsonwebtoken_1.default.sign({ id: this.id }, secrets_1.ACCESS_TOKEN_SECRET, { expiresIn: (0, jwt_1.expiredFormat)(secrets_1.ACCESS_TOKEN_EXPIRE) });
    }
    signRefreshToken() {
        return jsonwebtoken_1.default.sign({ id: this.id }, secrets_1.REFRESH_TOKEN_SECRET, { expiresIn: (0, jwt_1.expiredFormat)(secrets_1.REFRESH_TOKEN_EXPIRE) });
    }
    cleanUser() {
        const _a = this, { password } = _a, userWithoutPassword = __rest(_a, ["password"]); // Exclure le mot de passe
        return userWithoutPassword; // Retourner l'objet sans le mot de passe
    }
}
exports.UserEntity = UserEntity;
