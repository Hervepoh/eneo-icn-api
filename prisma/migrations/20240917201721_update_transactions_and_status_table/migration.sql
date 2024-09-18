/*
  Warnings:

  - The primary key for the `status` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to alter the column `id` on the `status` table. The data in that column could be lost. The data in that column will be cast from `Char(36)` to `Int`.
  - You are about to alter the column `statusId` on the `transactions` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Int`.

*/
-- DropForeignKey
ALTER TABLE `transactions` DROP FOREIGN KEY `transactions_statusId_fkey`;

-- AlterTable
ALTER TABLE `status` DROP PRIMARY KEY,
    MODIFY `id` INTEGER NOT NULL AUTO_INCREMENT,
    ADD PRIMARY KEY (`id`);

-- AlterTable
ALTER TABLE `transactions` MODIFY `statusId` INTEGER NOT NULL DEFAULT 1;

-- AddForeignKey
ALTER TABLE `transactions` ADD CONSTRAINT `transactions_statusId_fkey` FOREIGN KEY (`statusId`) REFERENCES `status`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
