import { Request, Response } from "express";

import asyncHandler from "express-async-handler";
import { prisma } from "../..";
import { hashToken } from "../../utils/userUtils";

export const verifyUser = asyncHandler(async (req: Request, res: Response) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);
  const userToken = await prisma.token.findFirst({
      where: {
          verificationToken: hashedToken,
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
  if (user?.isVerified) {
      res.status(400);
      throw new Error("User is already verified");
  }

  // Now Verify the user
  await prisma.user.update({
      where: { id: user?.id },
      data: {
          isVerified: true,
      },
  });

  res.status(200).json({ message: "Account verification Successful" });
});