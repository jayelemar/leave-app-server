import { Router } from 'express'
import { protect } from '../middlewares/authMiddleware'
import { sendEmail, sendLoginCode, sendVerificationEmail } from '../controllers/mail'

const userRoutes: Router = Router()

userRoutes.post('/send-email', protect, sendEmail)
userRoutes.post('/send-verification-email', protect, sendVerificationEmail)
userRoutes.post('/send-login-code/:email', sendLoginCode)

export default userRoutes
