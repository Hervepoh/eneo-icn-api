"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.executeQuery = void 0;
exports.getConnection = getConnection;
exports.releaseConnection = releaseConnection;
const db_config_1 = require("../../config/db.config");
const http_exception_1 = __importStar(require("../../exceptions/http-exception"));
var oracledb = require('oracledb');
// Function to establish a connection to the database
function getConnection() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const connection = yield oracledb.getConnection(db_config_1.dbConfig);
            return connection;
        }
        catch (err) {
            console.error('Erreur lors de la connexion à la base de données:', err);
            throw err;
        }
    });
}
// Function to close the database connection
function releaseConnection(connection) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield connection.close();
        }
        catch (err) {
            console.error('Erreur lors de la fermeture de la connexion:', err);
            throw err;
        }
    });
}
// Function to runQuery (execute Query) in the database
const executeQuery = (query_1, ...args_1) => __awaiter(void 0, [query_1, ...args_1], void 0, function* (query, values = []) {
    let connection;
    try {
        // Fetch data from the database
        connection = yield getConnection();
        const result = yield connection.execute(query, values);
        return result;
    }
    catch (error) {
        // Catch the error and return and error response
        console.error('Internal error:', error);
        return new http_exception_1.default(error.message, 500, http_exception_1.ErrorCode.INTERNAL_EXCEPTION, error);
    }
    finally {
        // close the connection to the database
        if (connection) {
            yield releaseConnection(connection);
        }
    }
});
exports.executeQuery = executeQuery;
