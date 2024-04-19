import { Request, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'
import crypto from 'crypto'
import { hashToken } from '../../utils/userUtils'
import { AWS_EMAIL_USER, FRONTEND_URL } from '../../secrets'
import { sendAutoEmail } from '../../utils/sendEmail'

export const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  const userEmail = req.body.email

  const user = await prisma.user.findUnique({
    where: { email: userEmail },
  })

  if (!user) {
    res.status(404)
    throw new Error('No user with this email')
  }

  // Same as verification Email process
  // Check if token exist in DB
  const token = await prisma.token.findFirst({
    where: { userId: user.id },
  })
  // delete token if exist in DB
  if (token) {
    await prisma.token.delete({
      where: { userId: user.id },
    })
  }
  // Create reset token
  const resetToken = crypto.randomBytes(32).toString('hex') + user.id
  console.log(resetToken)

  // Hash token and save to DB
  const hashedToken = hashToken(resetToken)
  await prisma.token.create({
    data: {
      userId: user.id,
      resetToken: hashedToken,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 60 * (60 * 1000)), // 60 minutes
    },
  })

  // Create Reset URL
  const resetURL = `${FRONTEND_URL}/forgot-password/${resetToken}`

  // Send Email
  const subject = 'Reset Password Request'
  const send_to = user.email
  const sent_from = AWS_EMAIL_USER!
  const reply_to = 'no-reply@elemar.site'
  const template = 'forgotPassword'
  const name = user.name
  const link = resetURL

  try {
    await sendAutoEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({
      message: 'Reset Password Email Sent Successfully',
    })
  } catch (error) {
    res.status(500)
    throw new Error('Email not send, please try again.')
  }
})
