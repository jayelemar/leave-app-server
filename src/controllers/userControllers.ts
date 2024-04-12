import {Response, Request} from 'express'
import asyncHandler from 'express-async-handler'
import { compareSync, hashSync } from 'bcrypt';
import parser from 'ua-parser-js'
import * as jwt from 'jsonwebtoken' 
import crypto from 'crypto'
import Cryptr from 'cryptr'

import { prisma } from '..';
import { LoginUserSchema, RegisterUserSchema } from '../schema/userSchema';
import { generateToken, hashToken, sendHttpOnlyCookie } from '../utils/userUtils';
import { AuthenticatedRequest } from '../middlewares/authMiddleware';
import { AWS_EMAIL_USER, FRONTEND_URL, JWT_SECRET } from '../secrets';
import { sendAutoEmail } from '../utils/sendEmail';

const cryptr = new Cryptr(process.env.CRYPTR_KEY!, {saltLength: 10});

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
  const ua = parser(req.headers['user-agent']);
  const thisUserAgent: string = ua.ua;
  console.log(thisUserAgent);

  const allowedAgents = await prisma.userAgent.findMany({
    where: { id: user.id },
  })
  // check if thisUserAgent is on the allowedAgents
  const isAllowedAgent = allowedAgents.some(agent => agent.userAgent === thisUserAgent);

  // If not allowed trigger 2 Factor Auth
  if(!isAllowedAgent) {
    // Generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random()*900000)
    console.log(loginCode);
    // Encrypt login code before saving to DB
    const encrptedLoginCode = cryptr.encrypt(loginCode.toString())

    // Check if user have a token delete it.
    let userToken = await prisma.token.findFirst({
      where: { userId: user.id }
    })
  
    if( userToken ) {
      await prisma.token.delete({
        where: { userId: user.id }
      })
    }
     // Save token to DB
    await prisma.token.create({
      data: {
        userId: user.id,
        loginToken: encrptedLoginCode,
        createdAt: new Date,
        expiresAt: new Date (Date.now() + (60 * 60 * 1000)), // 60mins
      }
    })
    res.status(400)
    throw new Error("new browser or device detected.");
  }

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

export const sendVerificationEmail = asyncHandler(async ( 
  req:AuthenticatedRequest, res:Response 
) => {

  const userId = req.user?.id
  const user = await prisma.user.findUnique({
    where: { id: userId }
  })
// Validation
  if (!userId) {
    res.status(404);
    throw new Error('User ID not found.');
  }
  if (!user) {
    res.status(404)
    throw new Error("User not found.");
  }
  if (user.isVerified) {
    res.status(400)
    throw new Error("User is already verified.");
  }

// Check if token exist in DB
  let token = await  prisma.token.findFirst({
    where: { userId: userId}
  })
// delete token if exist in DB
  if(token) {
    await prisma.token.delete({
      where: { userId: userId}
    })
  }
// Create Verification Token 
  const verificationToken = crypto.randomBytes(32).toString("hex") + userId
  console.log(verificationToken);

// Hash token and save to DB
  const hashedToken = hashToken(verificationToken)
  await prisma.token.create({
    data: {
      userId: userId,
      verificationToken: hashedToken,
      createdAt: new Date(), 
      expiresAt: new Date(Date.now() + 60 * (60 * 1000)), // 60 minutes
    },
  });

// Create Verification URL
  const verificationURL = `${FRONTEND_URL}/verify/${verificationToken}`

// Send Email
  const subject = "Verify your Account"
  const send_to = user.email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = "no-reply@elemar.site"
  const template = "verifyEmail"
  const name = user.name
  const link = verificationURL

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
      message: "Verification Email Sent Successfully"
    })
  } catch (error) {
    res.status(500)
    throw new Error("Email not send, please try again.");
  }

});

export const verifyUser = asyncHandler(async ( req:Request, res:Response ) => {
  const { verificationToken } = req.params

  const hashedToken = hashToken(verificationToken)
  const userToken = await prisma.token.findFirst({
    where: { 
      verificationToken: hashedToken,
      expiresAt: { gt: new Date() }// greater than current date
    }
  })
  if(!userToken) {
    res.status(404)
    throw new Error("Invalid or Expired Token");
  }
  // Find User
  const user = await prisma.user.findFirst({
    where: { id: userToken.userId }
  })
  if(user?.isVerified) {
    res.status(400)
    throw new Error("User is already verified");
  }

  // Now Verify the user
  await prisma.user.update({
    where:{ id: user?.id },
    data: {
      isVerified: true
    }
  })

  res.status(200).json({ message: "Account verification Successful"})
});

export const forgotPassword = asyncHandler(async ( req:Request, res:Response ) => {
  const userEmail = req.body.email
  
  const user = await prisma.user.findUnique({
    where: { email: userEmail }
  })

  if(!user) {
    res.status(404)
    throw new Error("No user with this email");
  }

// Same as verification Email process
// Check if token exist in DB
  const token = await prisma.token.findFirst({
    where: { userId: user.id }
  })
// delete token if exist in DB
  if(token) {
    await prisma.token.delete({
      where: { userId: user.id }
    })
  }
// Create reset token
  const resetToken = crypto.randomBytes(32).toString("hex") + user.id
  console.log(resetToken);

  // Hash token and save to DB
  const hashedToken = hashToken(resetToken)
  await prisma.token.create({
    data: {
      userId: user.id,
      resetToken: hashedToken,
      createdAt: new Date(), 
      expiresAt: new Date(Date.now() + 60 * (60 * 1000)), // 60 minutes
    },
  });

  // Create Reset URL
  const resetURL = `${FRONTEND_URL}/forgot-password/${resetToken}`

  // Send Email
  const subject = "Reset Password Request"
  const send_to = user.email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = "no-reply@elemar.site"
  const template = "forgotPassword"
  const name = user.name
  const link = resetURL

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
      message: "Reset Password Email Sent Successfully"
    })
  } catch (error) {
    res.status(500)
    throw new Error("Email not send, please try again.");
  }
});

export const resetPassword = asyncHandler(async ( req:Request, res:Response ) => {
  const { resetToken } = req.params
  const newPassword = req.body.password


  //Same as verifyUser function
  const hashedToken = hashToken(resetToken)
  const userToken = await prisma.token.findFirst({
    where: { 
      resetToken: hashedToken,
      expiresAt: { gt: new Date() }// greater than current date
    }
  })
  if(!userToken) {
    res.status(404)
    throw new Error("Invalid or Expired Token");
  }
  // Find User
  const user = await prisma.user.findFirst({
    where: { id: userToken.userId }
  })
  // Reset Password
  await prisma.user.update({
    where:{ id: user?.id },
    data: {
      password: hashSync(newPassword, 10)
    }
  })

  res.status(200).json({ message: "Password has been successfully reset. Please log in"})
});

export const changePassword = asyncHandler(async ( req:AuthenticatedRequest, res:Response ) => {
  const { oldPassword, newPassword } = req.body
  const userId = req.user?.id

  const user = await prisma.user.findFirst({
    where: {id: userId}
  })

  if(!user) {
    res.status(404)
    throw new Error("User not found. please sign up");
  }

  if(!oldPassword || !newPassword) {
    res.status(400)
    throw new Error("Please enter old and new password");
  }
// Check if old password is correct
  const passwordIsCorrect = await compareSync(oldPassword, user.password)

//Save new password
  if(user && passwordIsCorrect) {
    await prisma.user.update({
      where: { id: userId },
      data: {
        password: hashSync(newPassword, 10)
      }
    })
    res.status(200).json({
      message: "Your password has been changed successfully. please proceed to log in"
    })
  } else {
    res.status(400)
    throw new Error("old password is Incorrect");
  }

//Create an email to notify user that password have change
  // Check if token exist in DB
  const token = await prisma.token.findFirst({
    where: { userId: user.id }
  })
  // delete token if exist in DB
  if(token) {
    await prisma.token.delete({
      where: { userId: user.id }
    })
  }
  // Create reset token
  const resetToken = crypto.randomBytes(32).toString("hex") + user.id
  console.log(resetToken);

  // Hash token and save to DB
  const hashedToken = hashToken(resetToken)
  await prisma.token.create({
    data: {
      userId: user.id,
      resetToken: hashedToken,
      createdAt: new Date(), 
      expiresAt: new Date(Date.now() + 60 * (60 * 1000)), // 60 minutes
    },
  });

  // Create Reset URL
  const resetURL = `${FRONTEND_URL}/forgot-password/${resetToken}`

  // Send Email
  const subject = "Change Password Notification"
  const send_to = user.email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = "no-reply@elemar.site"
  const template = "changePassword"
  const name = user.name
  const link = resetURL

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
      message: "Change Password Notification Email Sent Successfully"
    })
  } catch (error) {
    res.status(500)
    throw new Error("Email not send, please try again.");
  }
});

export const sendLoginCode = asyncHandler(async ( req:Request, res:Response ) => {
  const { email } = req.params
  const user = await prisma.user.findUnique({
    where: { email }
  })
  if(!user) {
    res.status(404)
    throw new Error("User not found");
  }

  // Find loginToken in DB
  let userToken = await prisma.token.findFirst({
    where: { 
        userId: user.id,
        expiresAt: {
            gt: new Date()
        }
    },
  });

  if (!userToken) {
    res.status(404)
    throw new Error("Invalid or Expired Token, please login again");
  }

  const encryptedLoginCode = userToken.loginToken
  const decryptedLoginCode = cryptr.decrypt(encryptedLoginCode)
  console.log(decryptedLoginCode);

  // Send Login Code
  const subject = "Login Access Code - LOGO"
  const send_to = email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = "no-reply@elemar.site"
  const template = "loginCode"
  const name = user.name
  const link = decryptedLoginCode

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
      message: `An access code has been sent to ${email}.`
    })
  } catch (error) {
    res.status(500)
    throw new Error("Email not send, please try again.");
  }
});

export const loginWithCode = asyncHandler(async ( req:Request, res:Response ) => {
  const { email } = req.params
  const { loginCode } = req.body

  const user = await prisma.user.findUnique({
    where: { email }
  })

  if(!user) {
    res.status(404)
    throw new Error("User not found");
  }

  if(!loginCode) {
    res.status(404)
    throw new Error("No login code found");
  }

  //Find User Login Token
  const userToken = await prisma.token.findFirst({
    where: { 
      userId: user.id,
      expiresAt: {
        gt: new Date()
      }
    }
  })

  if(!userToken) {
    res.status(404)
    throw new Error("Invalid or expired token, please login again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken)

  if(loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    // Register User Agent
    const ua = parser(req.headers["user-agent"])
    const thisUserAgent = ua.ua

    // Push the new user to the array of user agents
    await prisma.userAgent.create({
      data: {
        userAgent: thisUserAgent,
        user:  {
          connect: { id: user.id }
        }
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
  }
});



