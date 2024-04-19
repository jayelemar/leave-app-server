import { AuthenticatedRequest } from '../../middlewares/authMiddleware'
import { Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'

export const getUsers = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
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
      createdAt: 'desc',
    },
  })
  if (!users) {
    res.status(500)
    throw new Error('Something went wrong')
  }
  res.status(200).json(users)
})
