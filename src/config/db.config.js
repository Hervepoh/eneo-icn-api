"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pooldbConfig = exports.dbConfig = void 0;
const secrets_1 = require("../secrets");
/*----------------------------------------------------
          External Database configuration
----------------------------------------------------*/
const service = secrets_1.DATABASE_EXTERNAL_SERVICE_NAME;
const host = secrets_1.DATABASE_EXTERNAL_HOSTNAME;
const port = secrets_1.DATABASE_EXTERNAL_PORT;
const user = secrets_1.DATABASE_EXTERNAL_USERNAME;
const password = secrets_1.DATABASE_EXTERNAL_PASSWORD;
const connectString = `(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=${host})(PORT=${port}))(CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=${service})))`;
// Connection information for the Oracle database
exports.dbConfig = {
    user: user,
    password: password,
    connectString: connectString
};
// Pool Connection information for the Oracle database
exports.pooldbConfig = {
    user: user,
    password: password,
    connectString: connectString,
    poolMax: 10, // Maximum number of connections in the pool
    poolMin: 0, // Minimum number of connections in the pool
    poolIncrement: 1, // Number of connections to add when expanding the pool
    poolTimeout: 60 // Number of seconds of inactivity before a connection is closed
};
