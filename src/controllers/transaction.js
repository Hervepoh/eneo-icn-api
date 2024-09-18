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
exports.bulkSoftRemove = exports.bulkCreate = exports.softRemove = exports.remove = exports.update = exports.getById = exports.get = exports.create = void 0;
const redis_1 = require("../libs/utils/redis");
const prismadb_1 = __importDefault(require("../libs/prismadb"));
const formatter_1 = require("../libs/utils/formatter");
const transactions_1 = require("../schema/transactions");
const unauthorized_1 = __importDefault(require("../exceptions/unauthorized"));
const bad_requests_1 = __importDefault(require("../exceptions/bad-requests"));
const http_exception_1 = require("../exceptions/http-exception");
const app_config_1 = require("../config/app.config");
const secrets_1 = require("../secrets");
const roles_1 = require("../schema/roles");
const configuration_1 = __importDefault(require("../exceptions/configuration"));
const not_found_1 = __importDefault(require("../exceptions/not-found"));
const key = 'transactions';
// Handling create process
const create = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    // Validate input
    const parsedTransaction = transactions_1.transactionSchema.parse(req.body);
    // get the user information
    const user = yield prismadb_1.default.user.findFirst({
        where: { id: (_a = req.user) === null || _a === void 0 ? void 0 : _a.id },
    });
    if (!user)
        throw new unauthorized_1.default("Unauthorize ressource", http_exception_1.ErrorCode.UNAUTHORIZE);
    const transaction = yield prismadb_1.default.transaction.create({
        data: Object.assign(Object.assign({}, req.body), { payment_date: (0, formatter_1.parseDMY)(req.body.payment_date), createdBy: user.id, modifiedBy: user.id, userId: user.id }),
    });
    revalidateService(key);
    res.status(201).json({
        success: true,
        data: transaction,
    });
});
exports.create = create;
//-----------------------------------------------------------------------------
//             GET ALL TRANSACTIONS :  get /transactions
//-----------------------------------------------------------------------------
// Handling get process   
const get = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const soft = ((_a = req.user) === null || _a === void 0 ? void 0 : _a.role) !== "admin" ? { deleted: false } : {};
    let query = {
        include: {
            bank: {
                select: {
                    name: true,
                },
            },
            paymentMode: {
                select: {
                    name: true,
                },
            },
            status: {
                select: {
                    name: true,
                },
            },
            user: {
                select: {
                    name: true,
                },
            },
        },
        orderBy: { createdAt: 'desc' },
    };
    // Extracting the status filter from the request query
    const { status } = req.query;
    if (status) {
        const validStatus = yield prismadb_1.default.status.findFirst({
            where: { name: status.toString() },
        });
        if (!validStatus)
            throw new bad_requests_1.default('Invalid status filter', http_exception_1.ErrorCode.INVALID_DATA);
        query = Object.assign({ where: { statusId: validStatus.id } }, query);
    }
    ;
    const transactions = yield prismadb_1.default.transaction.findMany(query);
    // const result = transactions.map((item) => ({
    //   ...item,
    //   bank: item
    //   payment_mode: item.payment_mode ? item.payment_mode?.name : null,
    // }));
    revalidateService(key);
    return res.status(200).json({
        success: true,
        data: transactions,
    });
});
exports.get = get;
//-----------------------------------------------------------------------------
//             GET TRANSACTIONS BY ID : get /transactions/:id
//-----------------------------------------------------------------------------
// Handling the process GET transaction by ID 
const getById = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const id = req.params.id;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    let data;
    // check if the provided id is in the cache
    const isCachedExist = yield redis_1.redis.get(id);
    if (isCachedExist) {
        data = JSON.parse(isCachedExist);
    }
    else {
        data = yield prismadb_1.default.transaction.findUnique({
            where: { id: id },
            include: { bank: true }
        });
        // Put into Redis for caching futur purpose
        yield redis_1.redis.set(id, JSON.stringify(data), "EX", secrets_1.REDIS_SESSION_EXPIRE);
    }
    return res.status(200).json({
        success: true,
        data,
    });
});
exports.getById = getById;
//-----------------------------------------------------------------------------
//             UPDATE ROLE : put  /transactions/:id
//-----------------------------------------------------------------------------
// Handling Update transaction process
const update = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    let id = req.params.id;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    id = transactions_1.idSchema.parse(id);
    // Check body request param for Security purpose
    if (req.body.userId ||
        req.body.assignTo ||
        req.body.createdAt ||
        req.body.createdBy ||
        req.body.createdBy ||
        req.body.modifiedBy ||
        req.body.deleted ||
        req.body.deletedBy ||
        req.body.deletedAt) {
        throw new unauthorized_1.default("Unauthorize ressource", http_exception_1.ErrorCode.UNAUTHORIZE);
    }
    // get the user information
    const user = yield prismadb_1.default.user.findFirst({
        where: { id: (_a = req.user) === null || _a === void 0 ? void 0 : _a.id },
    });
    if (!user)
        throw new unauthorized_1.default("Unauthorize ressource", http_exception_1.ErrorCode.UNAUTHORIZE);
    let data = Object.assign(Object.assign({}, req.body), { modifiedBy: user.id });
    if (req.body.payment_date) {
        data = Object.assign(Object.assign({}, data), { payment_date: new Date(req.body.payment_date) });
    }
    // For publish the request
    if (req.body.status === app_config_1.appConfig.status[2]) {
        const request = yield prismadb_1.default.transaction.findFirst({
            where: { id: id }
        });
        if (!(request === null || request === void 0 ? void 0 : request.reference) && (request === null || request === void 0 ? void 0 : request.paymentDate)) {
            data = Object.assign(Object.assign({}, data), { reference: yield genereteICNRef(request.paymentDate) });
        }
    }
    // For validation
    if (req.body.status === app_config_1.appConfig.status[3]) {
        data = Object.assign(Object.assign({}, data), { validator: user.id, validetedAt: new Date() });
    }
    // For Reject
    if (req.body.status === app_config_1.appConfig.status[4]) {
        data = Object.assign(Object.assign({}, data), { validator: user.id, validetedAt: new Date(), refusal: true });
    }
    const result = yield prismadb_1.default.transaction.update({
        where: { id: id },
        data: data,
    });
    // Put into Redis for caching futur purpose
    yield redis_1.redis.set(id, JSON.stringify(result), "EX", secrets_1.REDIS_SESSION_EXPIRE);
    return res.status(200).json({
        success: true,
        message: "Resource updated successfully",
        data: result,
    });
});
exports.update = update;
//-----------------------------------------------------------------------------
//             DELETE TRANSACTIONS : delete  /transactions/:id
//-----------------------------------------------------------------------------
// Handling delete process
const remove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    let id = req.params.id;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    id = transactions_1.idSchema.parse(id);
    yield prismadb_1.default.transaction.delete({
        where: { id: id },
    });
    yield redis_1.redis.del(id);
    revalidateService(key);
    res.status(204).send();
});
exports.remove = remove;
//-----------------------------------------------------------------------------
//             SOFT-DELETE TRANSACTIONS : delete  /transactions/:id
//-----------------------------------------------------------------------------
// Handling delete process
const softRemove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    const request = yield prismadb_1.default.transaction.findUnique({
        where: { id: transactions_1.idSchema.parse(id) },
    });
    if (!request)
        throw new not_found_1.default("ressource not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    // get the user information
    const user = yield prismadb_1.default.user.findFirst({
        where: { id: (_a = req.user) === null || _a === void 0 ? void 0 : _a.id },
    });
    if (!user)
        throw new unauthorized_1.default("Unauthorize ressource", http_exception_1.ErrorCode.UNAUTHORIZE);
    yield prismadb_1.default.transaction.update({
        where: { id: id },
        data: {
            deleted: true,
            deletedBy: user.id,
            deletedAt: new Date(),
        },
    });
    yield redis_1.redis.del(id);
    revalidateService(key);
    res.status(204).send();
});
exports.softRemove = softRemove;
// Handling create role process
const bulkCreate = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    // Validate that the request body is an array
    const requests = req.body;
    if (!Array.isArray(requests) || requests.length === 0) {
        throw new bad_requests_1.default("Request body must be a non-empty array", http_exception_1.ErrorCode.INVALID_DATA);
    }
    const parsedData = roles_1.bulkCreateSchema.parse(req.body);
    // get the user information
    const user = yield prismadb_1.default.user.findFirst({
        where: { id: (_a = req.user) === null || _a === void 0 ? void 0 : _a.id },
    });
    if (!user)
        throw new unauthorized_1.default("Unauthorize ressource", http_exception_1.ErrorCode.UNAUTHORIZE);
    const payMode = yield prismadb_1.default.paymentMode.findFirst();
    if (!payMode)
        throw new configuration_1.default("Payment mode not found, please contact adminstrator", http_exception_1.ErrorCode.BAD_CONFIGURATION);
    const bank = yield prismadb_1.default.bank.findFirst();
    if (!payMode)
        throw new configuration_1.default("Payment mode not found, please contact adminstrator", http_exception_1.ErrorCode.BAD_CONFIGURATION);
    const validRequests = [];
    // Validate each request
    for (const requestData of requests) {
        const { name, amount, bank, payment_date } = requestData;
        console.log("requestData", requestData);
        // Validate required fields for each request
        if (!name || !amount || !bank || !payment_date) {
            throw new bad_requests_1.default("All fields (payment_date, name, amount, bank) are required for each request", http_exception_1.ErrorCode.INVALID_DATA);
        }
        // Generate a unique reference if it's not provided
        const uniqueReference = yield genereteICNRef((0, formatter_1.parseDMY)(payment_date));
        const data = transactions_1.transactionSchema.parse({
            reference: uniqueReference.reference,
            name,
            amount,
            bank: bank.id,
            payment_date: (0, formatter_1.parseDMY)(payment_date),
            payment_mode: payMode.id,
            createdBy: user.id,
            modifiedBy: user.id,
            userId: user.id,
        });
        validRequests.push(data);
    }
    // Insert all valid requests into the database
    //const createdRequests = await prismaClient.transaction.createMany(validRequests);
    res.status(201).json({
        success: true,
        //data: createdRequests,
    });
});
exports.bulkCreate = bulkCreate;
//---------------------------------------------------------
//            SOFT BULK DELETE REQUEST
//---------------------------------------------------------
// Handling soft delete process
const bulkSoftRemove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    let ids = req.body.ids; // Supposons que les IDs sont passés dans le corps de la requête
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        throw new bad_requests_1.default('Invalid params: IDs are required', http_exception_1.ErrorCode.INVALID_DATA);
    }
    ids = ids.map((id) => transactions_1.idSchema.parse(id));
    // Vérifiez si les requêtes existent
    const requests = yield prismadb_1.default.transaction.findMany({
        where: { id: { in: ids } },
    });
    if (requests.length !== ids.length) {
        throw new not_found_1.default('Invalid params: Some transactions not found', http_exception_1.ErrorCode.INVALID_DATA);
    }
    // Supprimez les transactions en masse
    yield prismadb_1.default.transaction.deleteMany({
        where: { id: { in: ids } },
    });
    // Supprimez les entrées correspondantes du cache Redis
    yield Promise.all(ids.map((item) => redis_1.redis.del(item)));
    return res.status(200).json({
        success: true,
        message: "Transactions deleted successfully",
    });
});
exports.bulkSoftRemove = bulkSoftRemove;
const revalidateService = (key) => __awaiter(void 0, void 0, void 0, function* () {
    const data = yield prismadb_1.default.transaction.findMany({
        orderBy: {
            createdAt: 'desc',
        },
    });
    yield redis_1.redis.set(key, JSON.stringify(data));
    return data;
});
/**
 * The function `generateICNRef` generates a new reference based on the current date and the last
 * reference in the database collection.
 * @param {Date} date - The `genereteICNRef` function is designed to generate a new reference based on
 * the provided date. It retrieves the last reference from a database collection, extracts the sequence
 * number from it, increments the sequence number, and creates a new reference using the current month
 * and year along with the updated sequence
 * @returns The `genereteICNRef` function returns a new ICN reference number that is generated based on
 * the current date and the last reference number stored in the database. The function first retrieves
 * the last reference number from the database, then calculates a new reference number by incrementing
 * the sequence number part of the last reference number. If there is no last reference number found,
 * it generates a new reference number
 */
function genereteICNRef(date) {
    return __awaiter(this, void 0, void 0, function* () {
        // Get last reference in the references database collection
        const lastReference = yield prismadb_1.default.reference.findFirst({
            orderBy: { createdAt: 'desc', }
        });
        let newReference;
        if (lastReference) {
            // Extraction du numéro de séquence à partir de la dernière référence
            const lastSequenceNumber = parseInt(lastReference.reference.slice(4));
            newReference = `${(0, formatter_1.getCurrentMonthYear)(date.toDateString())}${String(lastSequenceNumber + 1).padStart(6, '0')}`;
        }
        else {
            // Première référence
            newReference = `${(0, formatter_1.getCurrentMonthYear)(date.toDateString())}000001`;
        }
        return yield prismadb_1.default.reference.create({ data: { reference: newReference } });
    });
}
