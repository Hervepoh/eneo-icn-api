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
const client_1 = require("@prisma/client");
const bcrypt_1 = __importDefault(require("bcrypt"));
const enum_1 = require("../src/constants/enum");
const secrets_1 = require("../src/secrets");
const prisma = new client_1.PrismaClient();
// Liste des moyens de paiement
const paymentModes = ['CASH', 'VIREMENT'];
// Liste des banques
const banks = ['UBA', 'SGC', 'BGFI', 'NFC', 'BICEC', 'BEAC'];
// Liste des rôles
const status = [
    'deleted',
    "draft",
    "initiated",
    "validated",
    "rejected",
    "pending_commercial_input",
    "pending_finance_validation",
    "processing",
    "treated"
];
// Liste des rôles
const roles = ['ADMIN', 'USER', 'ASSIGNATOR', 'VALIDATOR', 'MANAGER'];
// Liste des permissions
const services = Object.values(enum_1.serviceType);
const permissions = [
    'CREATE', 'READ', 'WRITE', 'UPDATE', 'DELETE', 'BULKCREATE', 'BULKDELETE'
];
const servicePermissions = services.flatMap(service => permissions.map(permission => `${service}-${permission}`));
// Données des utilisateurs
const userData = [
    {
        name: 'admin',
        email: 'admin',
        password: 'admin'
    },
    {
        name: 'Alice',
        email: 'alice@prisma.io',
        password: 'password'
    },
    {
        name: 'Nilu',
        email: 'nilu@prisma.io',
        password: 'password'
    },
    {
        name: 'Mahmoud',
        email: 'mahmoud@prisma.io',
        password: 'password'
    },
];
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(`##########################`);
        console.log(`##      Start seeding   ##`);
        console.log(`##########################`);
        // Vider les tables
        yield prisma.bank.deleteMany({});
        yield prisma.connectionHistory.deleteMany({});
        yield prisma.internalNotification.deleteMany({});
        yield prisma.notification.deleteMany({});
        yield prisma.paymentMode.deleteMany({});
        yield prisma.userRole.deleteMany({});
        yield prisma.rolePermission.deleteMany({});
        yield prisma.permission.deleteMany({});
        yield prisma.role.deleteMany({});
        yield prisma.transactionDetail.deleteMany({});
        yield prisma.transaction.deleteMany({});
        yield prisma.user.deleteMany({});
        yield prisma.status.deleteMany({});
        console.log(`Tables cleared.`);
        // Créer les Banques
        const bankPromises = banks.map(item => prisma.bank.create({
            data: { name: item },
        }));
        const createdBanks = yield Promise.all(bankPromises);
        console.log(`Created banks: ${banks.join(', ')}`);
        // Créer les Banques
        const payModePromises = paymentModes.map(item => prisma.paymentMode.create({
            data: { name: item },
        }));
        const createdPaymentMode = yield Promise.all(payModePromises);
        console.log(`Created paymentModes: ${paymentModes.join(', ')}`);
        // Créer les permissions
        const permissionPromises = servicePermissions.map(permission => prisma.permission.create({
            data: { name: permission },
        }));
        const createdPermissions = yield Promise.all(permissionPromises);
        console.log(`Created permissions: ${servicePermissions.join(', ')}`);
        // Créer les roles
        const rolePromises = roles.map(role => prisma.role.create({
            data: { name: role },
        }));
        const createdRoles = yield Promise.all(rolePromises);
        console.log(`Created roles: ${roles.join(', ')}`);
        // Créer les utilisateurs
        const userPromises = userData.map((u) => __awaiter(this, void 0, void 0, function* () {
            return prisma.user.create({
                data: Object.assign(Object.assign({}, u), { password: yield bcrypt_1.default.hash(u.password, parseInt(secrets_1.SALT_ROUNDS || '10')) }),
            });
        }));
        const createdUsers = yield Promise.all(userPromises);
        createdUsers.forEach(user => {
            console.log(`Created user with id: ${user.id}`);
        });
        // (Optionnel) Associer les rôles aux utilisateurs
        const ID_ROLE_ADMIN = yield prisma.user.findFirst({
            where: { name: "ADMIN" }
        });
        yield prisma.userRole.create({
            data: {
                userId: ID_ROLE_ADMIN === null || ID_ROLE_ADMIN === void 0 ? void 0 : ID_ROLE_ADMIN.id,
                roleId: createdRoles[0].id,
            }
        });
        for (const user of createdUsers) {
            yield prisma.userRole.create({
                data: {
                    userId: user.id,
                    roleId: createdRoles[1].id,
                }
            });
        }
        // (Optionnel) Associer certaines permissions aux rôles
        for (const role of createdRoles) {
            for (const permission of createdPermissions) {
                const db = yield prisma.permission.findUnique({
                    where: { name: permission.name }
                });
                yield prisma.rolePermission.create({
                    data: {
                        roleId: role.id,
                        permissionId: db === null || db === void 0 ? void 0 : db.id,
                    }
                });
            }
        }
        // Créer les status
        const statusPromises = status.map(item => prisma.status.create({
            data: { name: item },
        }));
        const createdStatus = yield Promise.all(statusPromises);
        console.log(`Created status: ${status.join(', ')}`);
        console.log(`##########################`);
        console.log(`##   Seeding finished.  ##`);
        console.log(`##########################`);
    });
}
main()
    .then(() => __awaiter(void 0, void 0, void 0, function* () {
    yield prisma.$disconnect();
}))
    .catch((e) => __awaiter(void 0, void 0, void 0, function* () {
    console.error(e);
    yield prisma.$disconnect();
    process.exit(1);
}));
