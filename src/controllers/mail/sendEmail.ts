import { Request, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'
import { FRONTEND_URL } from '../../secrets'
import { sendAutoEmail } from '../../utils/sendEmail'

export const sendEmail = asyncHandler(async (req: Request, res: Response) => {
  const { subject, send_to, reply_to, template, url } = req.body

  //Validation
  const checkParameter = (parameter: string, paramName: string) => {
    if (!parameter) {
      res.status(400)
      throw new Error(`Missing email parameter: ${paramName}`)
    }
  }

  checkParameter(subject, 'subject')
  checkParameter(send_to, 'send_to')
  checkParameter(reply_to, 'reply_to')
  checkParameter(template, 'template')

  // get user
  const user = await prisma.user.findFirst({
    where: { email: send_to },
  })

  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  const sent_from = process.env.AWS_EMAIL_USER!
  const name = user.name
  const link = `${FRONTEND_URL}/${url}`

  try {
    await sendAutoEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({
      message: 'Email Sent Successfully',
    })
  } catch (error) {
    res.status(500)
    throw new Error('Email not send, please try again.')
  }
})
