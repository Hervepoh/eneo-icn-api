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
exports.bulkRemove = exports.bulkCreate = exports.remove = exports.update = exports.getById = exports.get = exports.create = void 0;
const redis_1 = require("../libs/utils/redis");
const prismadb_1 = __importDefault(require("../libs/prismadb"));
const not_found_1 = __importDefault(require("../exceptions/not-found"));
const http_exception_1 = require("../exceptions/http-exception");
const validation_1 = __importDefault(require("../exceptions/validation"));
const banks_1 = require("../schema/banks");
const bad_requests_1 = __importDefault(require("../exceptions/bad-requests"));
const key = 'banks';
// Handling create bank process
const create = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input
    const parsedBank = banks_1.bankSchema.parse(req.body);
    // search if the name already exists
    const isAlready = yield prismadb_1.default.bank.findFirst({ where: { name: parsedBank.name } });
    if (isAlready) {
        throw new validation_1.default(null, "Duplicate setting name", http_exception_1.ErrorCode.RESSOURCE_ALREADY_EXISTS);
    }
    const data = yield prismadb_1.default.bank.create({
        data: parsedBank,
    });
    revalidateService(key);
    res.status(201).json({
        success: true,
        data
    });
});
exports.create = create;
//-----------------------------------------------------------------------------
//             GET ALL BANK :  get /banks
//-----------------------------------------------------------------------------
// Handling the process GET banks 
const get = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    let data;
    const redis_data = yield redis_1.redis.get(key);
    if (redis_data) {
        data = JSON.parse(redis_data);
    }
    else {
        data = yield revalidateService(key);
    }
    res.status(200).json({
        success: true,
        data
    });
});
exports.get = get;
//-----------------------------------------------------------------------------
//             GET BANK BY ID : get /banks/:id
//-----------------------------------------------------------------------------
// Handling the process GET bank by ID 
const getById = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    const data = yield prismadb_1.default.bank.findUnique({
        where: { id: id },
    });
    if (!data)
        throw new not_found_1.default("Bank not found", http_exception_1.ErrorCode.RESSOURCE_NOT_FOUND);
    res.status(200).json({
        success: true,
        data
    });
});
exports.getById = getById;
//-----------------------------------------------------------------------------
//             UPDATE BANK : put  /banks/:id
//-----------------------------------------------------------------------------
// Handling Update bank process
const update = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    const parsedBank = banks_1.bankSchema.parse(req.body); // Validate input
    const data = yield prismadb_1.default.bank.update({
        where: { id: id },
        data: parsedBank,
    });
    revalidateService(key);
    res.status(200).json({
        success: true,
        data
    });
});
exports.update = update;
//-----------------------------------------------------------------------------
//             DELETE BANK : delete  /banks/:id
//-----------------------------------------------------------------------------
// Handling delete bank process
const remove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    if (!id)
        throw new bad_requests_1.default('Invalid params', http_exception_1.ErrorCode.INVALID_DATA);
    yield prismadb_1.default.bank.delete({
        where: { id: id },
    });
    revalidateService(key);
    res.status(204).send(); // No content
});
exports.remove = remove;
// Handling create bank process
const bulkCreate = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input
    const parsedData = banks_1.bulkCreateSchema.parse(req.body);
    // Check for duplicate bank names
    const existingRessources = yield Promise.all(parsedData.data.map((item) => __awaiter(void 0, void 0, void 0, function* () {
        return yield prismadb_1.default.bank.findFirst({ where: { name: item.name } });
    })));
    const duplicates = existingRessources.filter(item => item);
    if (duplicates.length > 0) {
        return res.status(422).json({
            success: false,
            message: "Duplicate setting names found",
            duplicates: duplicates.map(item => item === null || item === void 0 ? void 0 : item.name)
        });
    }
    // Create banks
    const createdBanks = yield Promise.all(parsedData.data.map(bank => prismadb_1.default.bank.create({ data: bank })));
    revalidateService(key);
    res.status(201).json({
        success: true,
        data: createdBanks
    });
});
exports.bulkCreate = bulkCreate;
// Handling bulk delete bank process
const bulkRemove = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate input using Zod
    const { ids } = banks_1.bulkDeleteSchema.parse(req.body);
    // Perform bulk delete
    const deleteResult = yield prismadb_1.default.bank.deleteMany({
        where: {
            id: { in: ids } // Use 'in' to delete all matching IDs in one query
        }
    });
    revalidateService(key);
    // Send response
    res.status(204).send(); // No content
});
exports.bulkRemove = bulkRemove;
const revalidateService = (key) => __awaiter(void 0, void 0, void 0, function* () {
    const data = yield prismadb_1.default.bank.findMany({
        orderBy: {
            createdAt: 'desc',
        },
    });
    yield redis_1.redis.set(key, JSON.stringify(data));
    return data;
});
