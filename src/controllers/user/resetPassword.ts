import { Request, Response } from "express";
import asyncHandler from "express-async-handler";
import { prisma } from "../..";
import { hashToken } from "../../utils/userUtils";
import { hashSync } from "bcrypt";

export const resetPassword = asyncHandler(
  async (req: Request, res: Response) => {
      const { resetToken } = req.params;
      const newPassword = req.body.password;

      //Same as verifyUser function
      const hashedToken = hashToken(resetToken);
      const userToken = await prisma.token.findFirst({
          where: {
              resetToken: hashedToken,
              expiresAt: { gt: new Date() }, // greater than current date
          },
      });
      if (!userToken) {
          res.status(404);
          throw new Error("Invalid or Expired Token");
      }
      // Find User
      const user = await prisma.user.findFirst({
          where: { id: userToken.userId },
      });
      // Reset Password
      await prisma.user.update({
          where: { id: user?.id },
          data: {
              password: hashSync(newPassword, 10),
          },
      });

      res.status(200).json({
          message: "Password has been successfully reset. Please log in",
      });
  }
);