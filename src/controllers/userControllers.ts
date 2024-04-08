import {Response, Request} from 'express'
import asyncHandler from 'express-async-handler'
import { LoginUserSchema, RegisterUserSchema } from '../schema/userSchema';
import { prisma } from '..';
import { compareSync, hashSync } from 'bcrypt';
import { generateToken, sendHttpOnlyCookie } from '../utils/userUtils';
import parser from 'ua-parser-js'
import { AuthenticatedRequest } from '../middlewares/authMiddleware';
import { FRONTEND_URL, JWT_SECRET } from '../secrets';
import * as jwt from 'jsonwebtoken' 
import { sendAutoEmail } from '../utils/sendEmail';

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
    res.status(404);
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
    res.status(404)
    throw new Error("User not found.")
  }
  res.status(200).json(user)
});

export const updateUser = asyncHandler(async ( req:AuthenticatedRequest, res:Response ) => {
  const userId = req.user?.id
  const user = await prisma.user.findUnique({
    where: { id: userId },
  })
  
  if(!user) {
    res.status(404);
    throw new Error ("User not Found")
  }

  const { name, photo, phone, bio, ...userData } = user;
  const updatedUser = await prisma.user.update({
    where: { id: userId },
    data: {
      name: req.body.name || name,
      phone: req.body.phone || phone,
      bio: req.body.bio || bio,
      photo: req.body.photo || photo,
    }
  })

  res.status(200).json({
    name: updatedUser.name,
    photo: updatedUser.photo,
    phone: updatedUser.phone,
    bio: updatedUser.bio,
    ...userData
  })
});

export const deleteUser = asyncHandler(async ( req:AuthenticatedRequest, res:Response ) => {
  const userId = req.params.id
  if(!userId) {
    res.status(404)
    throw new Error("User not found.");
  }

  try {
    // Delete related UserAgents first
    await prisma.userAgent.deleteMany({
      where: {
        userId: userId,
      },
    });

    // Delete related Tokens
    await prisma.token.deleteMany({
      where: {
        userId: userId,
      },
    });

    // Then delete the user
    await prisma.user.delete({
      where: {
        id: userId,
      },
    });

    res.status(200).json({message: "User deleted Successfully"})
    
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Failed to delete user" });
  }
});

export const getUsers = asyncHandler(async ( req:AuthenticatedRequest, res:Response ) => {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      photo: true,
      phone: true,
      bio: true,
      role: true,
      isVerified: true,
      token: true,
    },
    orderBy: {
      createdAt: 'desc'
    }
  });
  if(!users) {
    res.status(500)
    throw new Error("Something went wrong");
  }
  res.status(200).json(users)
});

export const loginStatus = asyncHandler(async ( req:Request, res:Response ) => {
  const token = req.cookies.token
  if(!token) {
    res.json(false)
  }

// Verify Token
  const verified = jwt.verify(token, JWT_SECRET)
  if(verified) {
    res.json(true)
  } else {
    res.json(false)
  }
});

export const upgradeUser = asyncHandler(async ( req:AuthenticatedRequest, res:Response ) => {
  const { role, id } = req.body

  if (!id || !role) {
    res.status(400).json({ message: "Both 'id' and 'role' are required." });
    return;
  }
  
  const userId = id
  const userRole = role

  const user = await prisma.user.findUnique({
    where: { id: userId }
  })

  if (!user) {
    res.status(404)
    throw new Error("User not found.");
  }

  await prisma.user.update({
    where: { id: userId },
    data: {
      role: userRole,
    }
  })
  res.status(200).json({
    message: `User role updated to ${role}`
  })
});

export const sendEmail = asyncHandler(async ( req:Request, res:Response ) => {
  const { 
    subject,
    send_to,
    reply_to,
    template,
    url
  } = req.body

  //Validation
  const checkParameter = (parameter: string, paramName: string) => {
    if (!parameter) {
      res.status(400);
      throw new Error(`Missing email parameter: ${paramName}`);
    }
  };

  checkParameter(subject, 'subject');
  checkParameter(send_to, 'send_to');
  checkParameter(reply_to, 'reply_to');
  checkParameter(template, 'template');

  // get user
  const user = await prisma.user.findFirst({
    where: { email: send_to }
  })  

  if(!user) {
    res.status(404)
    throw new Error("User not found");
  }

  const sent_from = process.env.AWS_EMAIL_USER!
  const name = user.name
  const link = `${FRONTEND_URL}/${url}`

  try {
    await sendAutoEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    )
    res.status(200).json({
      message: "Email Sent Successfully"
    })
  } catch (error) {
    res.status(500)
    throw new Error("Email not send, please try again.");
  }
});

