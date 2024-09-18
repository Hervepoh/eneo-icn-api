"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.appConfig = void 0;
require("dotenv").config();
exports.appConfig = {
    status: [
        'deleted',
        "draft",
        "initiated",
        "validated",
        "rejected",
        "pending_commercial_input",
        "pending_finance_validation",
        "processing",
        "treated"
    ]
};
