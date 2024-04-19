import { NextFunction, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { AuthenticatedRequest } from '../../types/AuthenticatedRequest'

export const subAdminOnly = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const user = req.user
  if (user && (user.role === 'ADMIN' || user.role === 'SUB_ADMIN')) {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized as sub admin.')
  }
})
