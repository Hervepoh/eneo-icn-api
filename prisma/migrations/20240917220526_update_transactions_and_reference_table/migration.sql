/*
  Warnings:

  - You are about to drop the column `referenceId` on the `transactions` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[reference]` on the table `transactions` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE `transactions` DROP FOREIGN KEY `transactions_referenceId_fkey`;

-- AlterTable
ALTER TABLE `transactions` DROP COLUMN `referenceId`,
    ADD COLUMN `reference` VARCHAR(191) NULL;

-- CreateIndex
CREATE UNIQUE INDEX `transactions_reference_key` ON `transactions`(`reference`);
