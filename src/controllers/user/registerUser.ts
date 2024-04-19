import { Response, Request } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'
import parser from 'ua-parser-js'
import { hashSync } from 'bcrypt'
import { generateToken, sendHttpOnlyCookie } from '../../utils/userUtils'
import { RegisterUserSchema } from '../../schema/auth/RegisterUserSchema'

export const registerUser = asyncHandler(async (req: Request, res: Response) => {
  // Validation
  RegisterUserSchema.parse(req.body)

  const { name, email, password } = req.body

  // Check if user email already exist in DB
  const userExist = await prisma.user.findFirst({
    where: { email },
  })
  if (userExist) {
    res.status(400)
    throw new Error('Email has already been registered.')
  }

  // Get UserAgent
  const ua = parser(req.headers['user-agent'])
  const userAgent: string = ua.ua

  // Create user
  const user = await prisma.user.create({
    data: {
      name,
      email,
      password: hashSync(password, 10),
      userAgents: { create: [{ userAgent }] },
    },
  })
  // Generate Token
  const token = generateToken(user.id)

  // Send HTTP-only cookie
  sendHttpOnlyCookie(res, token)

  if (user) {
    const { ...userData } = user
    res.status(200).json({
      ...userData,
      token,
    })
  } else {
    res.status(400)
    throw new Error('Invalid user data.')
  }
})
