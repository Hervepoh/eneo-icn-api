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
Object.defineProperty(exports, "__esModule", { value: true });
const db_config_1 = require("../../config/db.config");
var oracledb = require('oracledb');
function getConnection() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield oracledb.createPool(db_config_1.dbConfig, (err) => {
                if (err) {
                    console.error('Erreur de création du pool de connexions Oracle :', err);
                    return;
                }
                console.log('Pool de connexions Oracle créé avec succès.');
            });
            return yield oracledb.getConnection();
        }
        catch (err) {
            console.error('Erreur lors de l\'obtention d\'une connexion :', err);
            throw err;
        }
    });
}
function executeQuery(connection, query, values) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const result = yield connection.execute(query);
            console.log('Résultat de la requête :', result);
        }
        catch (err) {
            console.error('Erreur lors de l\'exécution de la requête :', err);
            throw err;
        }
        finally {
            try {
                yield connection.close();
            }
            catch (err) {
                console.error('Erreur lors de la fermeture de la connexion :', err);
            }
        }
    });
}
// Function to close database pool 
function releaseConnection() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield oracledb.getPool().close(0);
        }
        catch (err) {
            console.error('Erreur lors de la fermeture du pool de connexions :', err);
            throw err;
        }
    });
}
function run(query, values) {
    return __awaiter(this, void 0, void 0, function* () {
        let connection;
        try {
            const connection = yield getConnection();
            let query = '';
            let values = [];
            yield executeQuery(connection, query, values);
        }
        catch (err) {
            console.error('Erreur dans la fonction run :', err);
        }
        finally {
            if (connection) {
                yield releaseConnection();
            }
        }
    });
}
