/*
  Warnings:

  - You are about to drop the `_user_roles` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE `_user_roles` DROP FOREIGN KEY `_user_roles_A_fkey`;

-- DropForeignKey
ALTER TABLE `_user_roles` DROP FOREIGN KEY `_user_roles_B_fkey`;

-- DropTable
DROP TABLE `_user_roles`;
