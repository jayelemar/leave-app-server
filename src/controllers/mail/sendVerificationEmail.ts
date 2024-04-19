import { Response } from 'express'
import { AuthenticatedRequest } from '../../middlewares/authMiddleware'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'
import crypto from 'crypto'
import { hashToken } from '../../utils/userUtils'
import { AWS_EMAIL_USER, FRONTEND_URL } from '../../secrets'
import { sendAutoEmail } from '../../utils/sendEmail'

export const sendVerificationEmail = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.id
  const user = await prisma.user.findUnique({
    where: { id: userId },
  })
  // Validation
  if (!userId) {
    res.status(404)
    throw new Error('User ID not found.')
  }
  if (!user) {
    res.status(404)
    throw new Error('User not found.')
  }
  if (user.isVerified) {
    res.status(400)
    throw new Error('User is already verified.')
  }

  // Check if token exist in DB
  let token = await prisma.token.findFirst({
    where: { userId: userId },
  })
  // delete token if exist in DB
  if (token) {
    await prisma.token.delete({
      where: { userId: userId },
    })
  }
  // Create Verification Token
  const verificationToken = crypto.randomBytes(32).toString('hex') + userId
  console.log(verificationToken)

  // Hash token and save to DB
  const hashedToken = hashToken(verificationToken)
  await prisma.token.create({
    data: {
      userId: userId,
      verificationToken: hashedToken,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 60 * (60 * 1000)), // 60 minutes
    },
  })

  // Create Verification URL
  const verificationURL = `${FRONTEND_URL}/verify/${verificationToken}`

  // Send Email
  const subject = 'Verify your Account'
  const send_to = user.email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = 'no-reply@elemar.site'
  const template = 'verifyEmail'
  const name = user.name
  const link = verificationURL

  try {
    await sendAutoEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({
      message: 'Verification Email Sent Successfully',
    })
  } catch (error) {
    res.status(500)
    throw new Error('Email not send, please try again.')
  }
})
