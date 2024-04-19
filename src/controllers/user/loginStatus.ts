import { Request, Response } from 'express'
import asyncHandler from 'express-async-handler'
import * as jwt from 'jsonwebtoken'
import { JWT_SECRET } from '../../secrets'

export const loginStatus = asyncHandler(async (req: Request, res: Response) => {
  const token = req.cookies.token
  if (!token) {
    res.json(false)
  }

  // Verify Token
  const verified = jwt.verify(token, JWT_SECRET)
  if (verified) {
    res.json(true)
  } else {
    res.json(false)
  }
})
