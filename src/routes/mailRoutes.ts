import { Router } from 'express'
import { sendEmail, sendLoginCode, sendVerificationEmail } from '../controllers/mail'
import { protect } from '../middlewares/auth'

const userRoutes: Router = Router()

userRoutes.post('/send-email', protect, sendEmail)
userRoutes.post('/send-verification-email', protect, sendVerificationEmail)
userRoutes.post('/send-login-code/:email', sendLoginCode)

export default userRoutes
