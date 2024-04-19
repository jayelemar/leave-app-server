import { Request, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'
import Cryptr from 'cryptr'
import parser from 'ua-parser-js'
import { generateToken, sendHttpOnlyCookie } from '../../utils/userUtils'

const cryptr = new Cryptr(process.env.CRYPTR_KEY!, { saltLength: 10 })

export const loginWithCode = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.params
  const { loginCode } = req.body // string

  const user = await prisma.user.findUnique({
    where: { email },
  })

  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  if (!loginCode) {
    res.status(404)
    throw new Error('No login code found')
  }

  //Find User Login Token
  const userToken = await prisma.token.findFirst({
    where: {
      userId: user.id,
      expiresAt: {
        gt: new Date(),
      },
    },
  })

  if (!userToken) {
    res.status(404)
    throw new Error('Invalid or expired token, please login again')
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken)

  if (loginCode !== decryptedLoginCode) {
    res.status(400)
    throw new Error('Incorrect login code, please try again')
  } else {
    // Register User Agent
    const ua = parser(req.headers['user-agent'])
    const thisUserAgent = ua.ua

    // Push the new user to the array of user agents
    await prisma.userAgent.create({
      data: {
        userAgent: thisUserAgent,
        user: {
          connect: { id: user.id },
        },
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
  }
})
