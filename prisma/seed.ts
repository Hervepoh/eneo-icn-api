import { PrismaClient, Prisma } from '@prisma/client';
import bcrypt from 'bcrypt';
import { serviceType } from '../src/constants/enum';
import { SALT_ROUNDS } from '../src/secrets';

const prisma = new PrismaClient();

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
const services = Object.values(serviceType);
const permissions = [
  'CREATE', 'READ', 'WRITE' ,'UPDATE', 'DELETE', 'BULKCREATE', 'BULKDELETE'
];
const servicePermissions = services.flatMap(service =>
  permissions.map(permission => `${service}-${permission}`)
);

// Données des utilisateurs
const userData: Prisma.UserCreateInput[] = [
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

async function main() {
  console.log(`##########################`);
  console.log(`##      Start seeding   ##`);
  console.log(`##########################`);


  // Vider les tables
  await prisma.bank.deleteMany({});
  await prisma.connectionHistory.deleteMany({});
  await prisma.internalNotification.deleteMany({});
  await prisma.notification.deleteMany({});
  await prisma.paymentMode.deleteMany({});
  await prisma.userRole.deleteMany({});
  await prisma.rolePermission.deleteMany({});
  await prisma.permission.deleteMany({});
  await prisma.role.deleteMany({});
  await prisma.transactionDetail.deleteMany({});
  await prisma.transaction.deleteMany({});
  await prisma.user.deleteMany({});
  await prisma.status.deleteMany({});

  console.log(`Tables cleared.`);

  // Créer les Banques
  const bankPromises = banks.map(item =>
    prisma.bank.create({
      data: { name: item },
    })
  );
  const createdBanks = await Promise.all(bankPromises);
  console.log(`Created banks: ${banks.join(', ')}`);

  // Créer les Banques
  const payModePromises = paymentModes.map(item =>
    prisma.paymentMode.create({
      data: { name: item },
    })
  );
  const createdPaymentMode = await Promise.all(payModePromises);
  console.log(`Created paymentModes: ${paymentModes.join(', ')}`);

  // Créer les permissions
  const permissionPromises = servicePermissions.map(permission =>
    prisma.permission.create({
      data: { name: permission! },
    })
  );
  const createdPermissions = await Promise.all(permissionPromises);
  console.log(`Created permissions: ${servicePermissions.join(', ')}`);

  // Créer les roles
  const rolePromises = roles.map(role =>
    prisma.role.create({
      data: { name: role },
    })
  );
  const createdRoles = await Promise.all(rolePromises);
  console.log(`Created roles: ${roles.join(', ')}`);

  // Créer les utilisateurs
  const userPromises = userData.map(async u =>
    prisma.user.create({
      data: {
        ...u,
        password: await bcrypt.hash(u.password, parseInt(SALT_ROUNDS || '10')!)
      },
    })
  );
  const createdUsers = await Promise.all(userPromises);
  createdUsers.forEach(user => {
    console.log(`Created user with id: ${user.id}`);
  });

  // (Optionnel) Associer les rôles aux utilisateurs
  const ID_ROLE_ADMIN = await prisma.user.findFirst({
    where: { name: "ADMIN" }
  })
  await prisma.userRole.create({
    data: {
      userId: ID_ROLE_ADMIN?.id!,
      roleId: createdRoles[0].id,
    }
  });

  for (const user of createdUsers) {
    await prisma.userRole.create({
      data: {
        userId: user.id,
        roleId: createdRoles[1].id,
      }
    });
  }


  // (Optionnel) Associer certaines permissions aux rôles
  for (const role of createdRoles) {
    for (const permission of createdPermissions) {
      const db = await prisma.permission.findUnique({
        where: { name: permission.name }
      })
      await prisma.rolePermission.create({
        data: {
          roleId: role.id,
          permissionId: db?.id!,
        }
      });
    }
  }

  // Créer les status
  const statusPromises = status.map(item =>
    prisma.status.create({
      data: { name: item },
    })
  );
  const createdStatus = await Promise.all(statusPromises);
  console.log(`Created status: ${status.join(', ')}`);

  console.log(`##########################`);
  console.log(`##   Seeding finished.  ##`);
  console.log(`##########################`);
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });