import { NextFunction, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { AuthenticatedRequest } from '../../types/AuthenticatedRequest'
import { JWT_SECRET } from '../../secrets'
import jwt from 'jsonwebtoken'
import { prisma } from '../..'

export const protect = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    // Get token from cookies
    const token = req.cookies.token

    if (!token) {
      res.status(401)
      throw new Error('Not authorized, please login2.')
    }

    // Verify token
    const verified = jwt.verify(token, JWT_SECRET) as { id: string }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: verified.id },
    })

    if (!user) {
      res.status(401)
      throw new Error('User not found')
    }

    // Check user role
    if (user.role !== 'SUSPENDED') {
      //  continue to the next middleware or route handler
      req.user = user
      next()
    } else {
      res.status(400)
      throw new Error('User suspended, please contact support.')
    }
  } catch (error) {
    res.status(401)
    throw new Error('Not authorized, please login.')
  }
})
