/*
  Warnings:

  - You are about to drop the `_role_permissions` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE `_role_permissions` DROP FOREIGN KEY `_role_permissions_A_fkey`;

-- DropForeignKey
ALTER TABLE `_role_permissions` DROP FOREIGN KEY `_role_permissions_B_fkey`;

-- DropTable
DROP TABLE `_role_permissions`;
