import { Request, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'
import { AWS_EMAIL_USER } from '../../secrets'
import { sendAutoEmail } from '../../utils/sendEmail'
import Cryptr from 'cryptr'

const cryptr = new Cryptr(process.env.CRYPTR_KEY!, { saltLength: 10 })

export const sendLoginCode = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.params
  const user = await prisma.user.findUnique({
    where: { email },
  })
  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  // Find loginToken in DB
  let userToken = await prisma.token.findFirst({
    where: {
      userId: user.id,
      expiresAt: {
        gt: new Date(),
      },
    },
  })

  if (!userToken) {
    res.status(404)
    throw new Error('Invalid or Expired Token, please login again')
  }

  const encryptedLoginCode = userToken.loginToken
  const decryptedLoginCode = cryptr.decrypt(encryptedLoginCode)
  console.log(decryptedLoginCode)

  // Send Login Code
  const subject = 'Login Access Code - LOGO'
  const send_to = email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = 'no-reply@elemar.site'
  const template = 'loginCode'
  const name = user.name
  const link = decryptedLoginCode

  try {
    await sendAutoEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({
      message: `An access code has been sent to ${email}.`,
    })
  } catch (error) {
    res.status(500)
    throw new Error('Email not send, please try again.')
  }
})
