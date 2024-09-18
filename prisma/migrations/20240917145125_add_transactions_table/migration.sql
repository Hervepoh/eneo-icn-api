-- CreateTable
CREATE TABLE `transactions` (
    `id` CHAR(36) NOT NULL,
    `reference` VARCHAR(191) NULL,
    `userId` CHAR(36) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `amount` DOUBLE NOT NULL,
    `bankId` CHAR(36) NOT NULL,
    `paymentDate` DATETIME(3) NOT NULL,
    `paymentModeId` CHAR(36) NOT NULL,
    `statusId` VARCHAR(191) NOT NULL DEFAULT 'draft',
    `assignTo` VARCHAR(191) NULL,
    `validatorId` CHAR(36) NULL,
    `validatedAt` DATETIME(3) NULL,
    `refusal` BOOLEAN NOT NULL DEFAULT false,
    `reasonForRefusal` VARCHAR(191) NULL,
    `createdBy` VARCHAR(191) NULL,
    `modifiedBy` VARCHAR(191) NULL,
    `deleted` BOOLEAN NOT NULL DEFAULT false,
    `deletedBy` VARCHAR(191) NULL,
    `deletedAt` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `transactions_reference_key`(`reference`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `transactions` ADD CONSTRAINT `transactions_statusId_fkey` FOREIGN KEY (`statusId`) REFERENCES `status`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `transactions` ADD CONSTRAINT `transactions_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `transactions` ADD CONSTRAINT `transactions_bankId_fkey` FOREIGN KEY (`bankId`) REFERENCES `banks`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `transactions` ADD CONSTRAINT `transactions_paymentModeId_fkey` FOREIGN KEY (`paymentModeId`) REFERENCES `payment_modes`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
