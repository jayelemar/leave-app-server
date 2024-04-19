import { AuthenticatedRequest } from '../../middlewares/authMiddleware'
import { Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'

export const deleteUser = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.params.id
  if (!userId) {
    res.status(404)
    throw new Error('User not found.')
  }

  try {
    // Delete related UserAgents first
    await prisma.userAgent.deleteMany({
      where: {
        userId: userId,
      },
    })

    // Delete related Tokens
    await prisma.token.deleteMany({
      where: {
        userId: userId,
      },
    })

    // Then delete the user
    await prisma.user.delete({
      where: {
        id: userId,
      },
    })

    res.status(200).json({ message: 'User deleted Successfully' })
  } catch (error) {
    console.error('Error deleting user:', error)
    res.status(500).json({ message: 'Failed to delete user' })
  }
})
