import { AuthenticatedRequest } from '../../middlewares/authMiddleware'
import { Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'

export const upgradeUser = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const { role, id } = req.body

  if (!id || !role) {
    res.status(400).json({
      message: "Both 'id' and 'role' are required.",
    })
    return
  }

  const userId = id
  const userRole = role

  const user = await prisma.user.findUnique({
    where: { id: userId },
  })

  if (!user) {
    res.status(404)
    throw new Error('User not found.')
  }

  await prisma.user.update({
    where: { id: userId },
    data: {
      role: userRole,
    },
  })
  res.status(200).json({
    message: `User role updated to ${role}`,
  })
})
