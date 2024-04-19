import { NextFunction, Request, Response } from 'express'
import asyncHandler from 'express-async-handler'
import jwt from 'jsonwebtoken'
import { JWT_SECRET } from '../secrets'
import { prisma } from '..'
import type { User } from '@prisma/client'

export interface AuthenticatedRequest extends Request {
  user?: User
}

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

export const adminOnly = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.role === 'ADMIN') {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized as admin.')
  }
})

export const subAdminOnly = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const user = req.user
  if (user && (user.role === 'ADMIN' || user.role === 'SUB_ADMIN')) {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized as sub admin.')
  }
})

export const verifiedOnly = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.isVerified) {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized, account is not verified.')
  }
})
