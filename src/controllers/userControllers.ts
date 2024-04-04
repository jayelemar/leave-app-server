import {Response, Request} from 'express'
import asyncHandler from 'express-async-handler'
import { LoginUserSchema, RegisterUserSchema } from '../schema/userSchema';
import { prisma } from '..';
import { compareSync, hashSync } from 'bcrypt';
import { generateToken, sendHttpOnlyCookie } from '../utils/userUtils';
import parser from 'ua-parser-js'
import { AuthenticatedRequest } from '../middlewares/authMiddleware';

export const registerUser = asyncHandler(async ( req:Request, res:Response ) => {
// Validation
  RegisterUserSchema.parse(req.body)

  const { name, email, password } = req.body
  
// Check if user email already exist in DB
  const userExist = await prisma.user.findFirst({
    where: { email }
  })
  if (userExist) {
    res.status(400)
    throw new Error("Email has already been registered.")
  }

// Get UserAgent
  const ua = parser(req.headers['user-agent']);
  const userAgent: string = ua.ua;

// Create user
  const user = await prisma.user.create({
    data: {
      name,
      email,
      password: hashSync(password, 10),
      userAgents: { create: [{ userAgent }] }
    }
  })
// Generate Token
  const token = generateToken(user.id)

// Send HTTP-only cookie
  sendHttpOnlyCookie(res, token)
  
  if(user) {
    const { ...userData } = user
    res.status(200).json({
      ...userData,
      token,
    })
  } else {
    res.status(400)
    throw new Error("Invalid user data.")
  }
});

export const loginUser = asyncHandler(async ( req:Request, res:Response ) => {
  // Validation
  LoginUserSchema.parse(req.body)
  const { email, password } = req.body

  // Check if user email already exist
  let user = await prisma.user.findFirst({
    where: { email }
  })
  if(!user) {
    res.status(400);
    throw new Error("User not found, please sign up")
  }
  const passwordIsCorrect = await compareSync(password, user.password)
  if(!passwordIsCorrect) {
    throw new Error("Incorrect Password, please try again");
  }

  // Trigger 2FA for unknown user Agent

  // Generate Token
  const token = generateToken(user.id)

  // Send Http Only Cookie
  sendHttpOnlyCookie(res, token)

  // Send JSon Response
  if(user) {
    const { ...userData } = user
    res.status(200).json({
      ...userData,
      token,
    })
  } else {
    res.status(400)
    throw new Error("Invalid user data");
  }
})

export const logoutUser = asyncHandler(async ( req:Request, res:Response ) => {
// Expire the cookie to logout  
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), // expire now
    sameSite: "none",
    secure: true,
  })

//Send Json Response
  res.status(200).json({ message: "User Logout Successfully"})
});

export const getUser = asyncHandler(async ( req:AuthenticatedRequest, res:Response ) => {
  const userId = req.user?.id
  const user = await prisma.user.findUnique({
    where: { id: userId },
  })
  if(!user){
    res.status(400)
    throw new Error("User not found.")
  }
  res.status(200).json(user)
});


