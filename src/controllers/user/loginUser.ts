import { Response, Request } from "express";
import asyncHandler from "express-async-handler";
import { prisma } from "../..";
import parser from "ua-parser-js";
import { generateToken, sendHttpOnlyCookie } from "../../utils/userUtils";
import { LoginUserSchema } from "../../schema/userSchema";
import { compareSync } from "bcrypt";

import Cryptr from "cryptr";

const cryptr = new Cryptr(process.env.CRYPTR_KEY!, { saltLength: 10 });

export const loginUser = asyncHandler(async (req: Request, res: Response) => {
  // Validation
  LoginUserSchema.parse(req.body);
  const { email, password } = req.body;

  // Check if user email already exist
  let user = await prisma.user.findFirst({
      where: { email },
  });
  if (!user) {
      res.status(404);
      throw new Error("User not found, please sign up");
  }
  const passwordIsCorrect = await compareSync(password, user.password);
  if (!passwordIsCorrect) {
      throw new Error("Incorrect Password, please try again");
  }

  // Trigger 2FA for unknown user Agent
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent: string = ua.ua;
  console.log(thisUserAgent);

  const allowedAgents = await prisma.userAgent.findMany({
      where: { userId: user.id },
  });
  console.log(allowedAgents);
  // check if thisUserAgent is on the allowedAgents
  const isAllowedAgent = allowedAgents.some(
      (agent) => agent.userAgent === thisUserAgent
  );

  // If not allowed trigger 2 Factor Auth
  if (!isAllowedAgent) {
      // Generate 6 digit code
      const loginCode = Math.floor(100000 + Math.random() * 900000);
      console.log(loginCode);
      // Encrypt login code before saving to DB
      const encrptedLoginCode = cryptr.encrypt(loginCode.toString());

      // Check if user have a token delete it.
      let userToken = await prisma.token.findFirst({
          where: { userId: user.id },
      });

      if (userToken) {
          await prisma.token.delete({
              where: { userId: user.id },
          });
      }
      // Save token to DB
      await prisma.token.create({
          data: {
              userId: user.id,
              loginToken: encrptedLoginCode,
              createdAt: new Date(),
              expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 60mins
          },
      });
      res.status(400);
      throw new Error("new browser or device detected.");
  }

  // Generate Token
  const token = generateToken(user.id);

  // Send Http Only Cookie
  sendHttpOnlyCookie(res, token);

  // Send JSon Response
  if (user) {
      const { ...userData } = user;
      res.status(200).json({
          ...userData,
          token,
      });
  } else {
      res.status(400);
      throw new Error("Invalid user data");
  }
});