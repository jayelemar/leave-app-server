import * as jwt from 'jsonwebtoken'
import { JWT_SECRET } from '../secrets'
import { Response } from 'express'
import crypto from 'crypto'

export const generateToken = (id: string) => {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: '1d' })
}

export const sendHttpOnlyCookie = (res: Response, token: string) => {
  try {
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true,
    })
  } catch (error) {
    console.error('Error setting cookie:', error)
  }
}

export const hashToken = (token: string) => {
  return crypto.createHash('sha256').update(token.toString()).digest('hex')
}
