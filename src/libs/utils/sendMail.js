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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ejs_1 = __importDefault(require("ejs"));
const path_1 = __importDefault(require("path"));
const nodemailer_1 = __importDefault(require("nodemailer"));
const mail_config_1 = require("../../config/mail.config");
const secrets_1 = require("../../secrets");
const sendMail = (options) => __awaiter(void 0, void 0, void 0, function* () {
    const transporter = nodemailer_1.default.createTransport(mail_config_1.mailConfig);
    const { email, subject, template, data } = options;
    // Get the path to the email templae file
    const templatePath = path_1.default.join(__dirname, "../../mails", template);
    // Render the email tamplate with EJS
    const html = yield ejs_1.default.renderFile(templatePath, data);
    const mailOptions = {
        from: secrets_1.SMTP_MAIL,
        to: email,
        subject,
        html
    };
    yield transporter.sendMail(mailOptions);
});
exports.default = sendMail;
