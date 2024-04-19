import { AuthenticatedRequest } from '../../middlewares/authMiddleware'
import { Response } from 'express'
import asyncHandler from 'express-async-handler'
import { prisma } from '../..'

export const updateUser = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.id
  const user = await prisma.user.findUnique({
    where: { id: userId },
  })

  if (!user) {
    res.status(404)
    throw new Error('User not Found')
  }

  const { name, photo, phone, bio, ...userData } = user
  const updatedUser = await prisma.user.update({
    where: { id: userId },
    data: {
      name: req.body.name || name,
      phone: req.body.phone || phone,
      bio: req.body.bio || bio,
      photo: req.body.photo || photo,
    },
  })

  res.status(200).json({
    name: updatedUser.name,
    photo: updatedUser.photo,
    phone: updatedUser.phone,
    bio: updatedUser.bio,
    ...userData,
  })
})
