import { NextFunction, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { AuthenticatedRequest } from '../../types/AuthenticatedRequest'

export const adminOnly = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.role === 'ADMIN') {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized as admin.')
  }
})
