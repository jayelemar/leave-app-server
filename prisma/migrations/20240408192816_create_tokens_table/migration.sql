/*
  Warnings:

  - You are about to drop the column `token` on the `token` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE `token` DROP COLUMN `token`,
    ADD COLUMN `loginToken` VARCHAR(191) NOT NULL DEFAULT '',
    ADD COLUMN `resetToken` VARCHAR(191) NOT NULL DEFAULT '',
    ADD COLUMN `verificationToken` VARCHAR(191) NOT NULL DEFAULT '';
