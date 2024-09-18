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
exports.getICN = exports.getICNGroupes = exports.getICNDematerializeCode = exports.getICNNextCode = exports.generationOfIntegrationFile = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const moment_1 = __importDefault(require("moment"));
const request_1 = require("../constants/request");
const db_oracle_1 = require("../libs/utils/db.oracle");
const bad_requests_1 = __importDefault(require("../exceptions/bad-requests"));
const http_exception_1 = require("../exceptions/http-exception");
//---------------------------------------------------------
//              GET ICN CODE 
//---------------------------------------------------------
const generationOfIntegrationFile = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Fetch data from the database
    // TODO : fix this part
    // const documents = await prismaClient.documents.findMany();
    // Création du contenu du fichier CSV
    let csvContent = `File Generated on=${(0, moment_1.default)().format('ddd MMM DD HH:mm:ss Z YYYY')}\nData for Date=${(0, moment_1.default)().format('DD/MM/YYYY')}|5701473|640816|3\n`;
    csvContent += 'Transaction_ID|Sub_transaction_Type|Bill_Partner_Company_name|Bill_partner_company_code|Bill_Number|Bill_Account_Number|Bill_Due_Date|Paid_Amount|Paid_Date|Paid_By_MSISDN|Transaction_Status|OM_Bill_Payment_Status\n';
    // TODO : fix this part
    // documents.forEach((doc) => {
    //   csvContent += `${doc.transaction_id}|${doc.sub_transaction_type}|${doc.bill_partner_company_name}|${doc.bill_partner_company_code}|${doc.bill_number}|${doc.bill_account_number}|${moment(doc.bill_due_date).format('DD/MM/YYYY HH:mm:ss')}|${doc.paid_amount}|${moment(doc.paid_date).format('DD/MM/YYYY HH:mm:ss')}|${doc.paid_by_msisdn}|${doc.transaction_status}|${doc.om_bill_payment_status}\n`;
    // });
    // Génération du nom de fichier
    const timestamp = (0, moment_1.default)().format('MMDDYYYYHHmmss');
    const fileName = `AES_${timestamp}_PAIDBILLS.csv`;
    // Génération du chemin du fichier
    const outputDir = path_1.default.join(__dirname, '../output');
    const filePath = path_1.default.join(outputDir, fileName);
    // Créer le répertoire 'output' s'il n'existe pas
    if (!fs_1.default.existsSync(outputDir)) {
        fs_1.default.mkdirSync(outputDir);
    }
    // Écriture du fichier
    fs_1.default.writeFileSync(filePath, csvContent);
    // send the response
    return res.status(200).json({
        success: true,
        file: `CSV file generated at ${filePath}`
    });
});
exports.generationOfIntegrationFile = generationOfIntegrationFile;
//---------------------------------------------------------
//              GET ICN CODE 
//---------------------------------------------------------
const getICNNextCode = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    // Fetch data from the database
    const result = yield (0, db_oracle_1.executeQuery)(request_1.sqlQuery.icn_next_code);
    // send the response
    return res.status(200).json({
        success: true,
        icn_code: (_a = result.rows[0][0]) !== null && _a !== void 0 ? _a : ""
    });
});
exports.getICNNextCode = getICNNextCode;
//---------------------------------------------------------
//              GET ICN DEMATERIALIZE CODE 
//---------------------------------------------------------
const getICNDematerializeCode = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    // Fetch data from the database
    const result = yield (0, db_oracle_1.executeQuery)(request_1.sqlQuery.icn_next_dematerialisation_code);
    // send the response
    return res.status(200).json({
        success: true,
        dematerialisation: (_a = result.rows[0][0]) !== null && _a !== void 0 ? _a : ""
    });
});
exports.getICNDematerializeCode = getICNDematerializeCode;
//---------------------------------------------------------
//              GET GROUPES
//---------------------------------------------------------
const getICNGroupes = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Fetch data from the database
    const result = yield (0, db_oracle_1.executeQuery)(request_1.sqlQuery.select_groupes);
    // send the response
    return res.status(200).json({
        success: true,
        groupes: result.rows
    });
});
exports.getICNGroupes = getICNGroupes;
//---------------------------------------------------------
//              GET GROUPES
//---------------------------------------------------------
const getICN = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id: icn_number, type } = req.body;
    // TODO :  Define the contraint due to the period 
    if (!icn_number) {
        throw new bad_requests_1.default("Invalid parameters", http_exception_1.ErrorCode.INVALID_DATA);
    }
    let query = "";
    let value = [];
    switch (type) {
        case "full":
            console.log("Full");
            query = request_1.sqlQuery.icn_fulldata;
            value = [icn_number];
            break;
        case "light":
            console.log("Light");
            query = request_1.sqlQuery.icn_lightdata;
            value = [icn_number, icn_number, icn_number];
            break;
        default:
            console.log("oTher");
            query = request_1.sqlQuery.icn_infos;
            value = [icn_number];
            break;
    }
    const result = yield (0, db_oracle_1.executeQuery)(query, value);
    // send the response
    return res.status(200).json({
        success: true,
        data: result.rows
    });
});
exports.getICN = getICN;
