/*
  Warnings:

  - The primary key for the `permissions` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- DropForeignKey
ALTER TABLE `_role_permissions` DROP FOREIGN KEY `_role_permissions_A_fkey`;

-- AlterTable
ALTER TABLE `_role_permissions` MODIFY `A` CHAR(36) NOT NULL;

-- AlterTable
ALTER TABLE `permissions` DROP PRIMARY KEY,
    MODIFY `id` CHAR(36) NOT NULL,
    ADD PRIMARY KEY (`id`);

-- AddForeignKey
ALTER TABLE `_role_permissions` ADD CONSTRAINT `_role_permissions_A_fkey` FOREIGN KEY (`A`) REFERENCES `permissions`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
