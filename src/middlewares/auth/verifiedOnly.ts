import { NextFunction, Response } from 'express'
import asyncHandler from 'express-async-handler'
import { AuthenticatedRequest } from '../../types/AuthenticatedRequest'

export const verifiedOnly = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.isVerified) {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized, account is not verified.')
  }
})
