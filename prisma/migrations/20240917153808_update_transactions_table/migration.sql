/*
  Warnings:

  - You are about to drop the column `assignTo` on the `transactions` table. All the data in the column will be lost.
  - You are about to drop the column `reference` on the `transactions` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[referenceId]` on the table `transactions` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX `transactions_reference_key` ON `transactions`;

-- AlterTable
ALTER TABLE `transactions` DROP COLUMN `assignTo`,
    DROP COLUMN `reference`,
    ADD COLUMN `referenceId` VARCHAR(191) NULL;

-- CreateIndex
CREATE UNIQUE INDEX `transactions_referenceId_key` ON `transactions`(`referenceId`);

-- AddForeignKey
ALTER TABLE `transactions` ADD CONSTRAINT `transactions_referenceId_fkey` FOREIGN KEY (`referenceId`) REFERENCES `references`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
