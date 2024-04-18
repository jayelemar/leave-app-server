import { AuthenticatedRequest } from "../../middlewares/authMiddleware";
import { Response } from "express";
import asyncHandler from "express-async-handler";
import { prisma } from "../..";
import { hashToken } from "../../utils/userUtils";
import { compareSync, hashSync } from "bcrypt";
import crypto from "crypto";
import { AWS_EMAIL_USER, FRONTEND_URL } from "../../secrets";
import { sendAutoEmail } from "../../utils/sendEmail";

export const changePassword = asyncHandler(
  async (req: AuthenticatedRequest, res: Response) => {
      const { oldPassword, newPassword } = req.body;
      const userId = req.user?.id;

      const user = await prisma.user.findFirst({
          where: { id: userId },
      });

      if (!user) {
          res.status(404);
          throw new Error("User not found. please sign up");
      }

      if (!oldPassword || !newPassword) {
          res.status(400);
          throw new Error("Please enter old and new password");
      }
      // Check if old password is correct
      const passwordIsCorrect = await compareSync(oldPassword, user.password);

      //Save new password
      if (user && passwordIsCorrect) {
          await prisma.user.update({
              where: { id: userId },
              data: {
                  password: hashSync(newPassword, 10),
              },
          });
          res.status(200).json({
              message:
                  "Your password has been changed successfully. please proceed to log in",
          });
      } else {
          res.status(400);
          throw new Error("old password is Incorrect");
      }

      //Create an email to notify user that password have change
      // Check if token exist in DB
      const token = await prisma.token.findFirst({
          where: { userId: user.id },
      });
      // delete token if exist in DB
      if (token) {
          await prisma.token.delete({
              where: { userId: user.id },
          });
      }
      // Create reset token
      const resetToken = crypto.randomBytes(32).toString("hex") + user.id;
      console.log(resetToken);

      // Hash token and save to DB
      const hashedToken = hashToken(resetToken);
      await prisma.token.create({
          data: {
              userId: user.id,
              resetToken: hashedToken,
              createdAt: new Date(),
              expiresAt: new Date(Date.now() + 60 * (60 * 1000)), // 60 minutes
          },
      });

      // Create Reset URL
      const resetURL = `${FRONTEND_URL}/forgot-password/${resetToken}`;

      // Send Email
      const subject = "Change Password Notification";
      const send_to = user.email;
      const sent_from = AWS_EMAIL_USER!;
      const reply_to = "no-reply@elemar.site";
      const template = "changePassword";
      const name = user.name;
      const link = resetURL;

      try {
          await sendAutoEmail(
              subject,
              send_to,
              sent_from,
              reply_to,
              template,
              name,
              link
          );
          res.status(200).json({
              message: "Change Password Notification Email Sent Successfully",
          });
      } catch (error) {
          res.status(500);
          throw new Error("Email not send, please try again.");
      }
  }
);