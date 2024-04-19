import { Response } from 'express'
import asyncHandler from 'express-async-handler'
import { AuthenticatedRequest } from '../../middlewares/authMiddleware'
import { prisma } from '../..'

export const getUser = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.id
  const user = await prisma.user.findUnique({
    where: { id: userId },
  })
  if (!user) {
    res.status(404)
    throw new Error('User not found.')
  }
  res.status(200).json(user)
})
