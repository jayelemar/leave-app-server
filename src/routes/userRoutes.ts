import { Router } from 'express'
import { deleteUser, forgotPassword, getUser, getUsers, loginStatus, loginUser, logoutUser, registerUser, resetPassword, sendEmail, sendVerificationEmail, updateUser, upgradeUser, verifyUser } from '../controllers/userControllers'
import { adminOnly, protect, subAdminOnly } from '../middlewares/authMiddleware'

const userRoutes:Router = Router()

userRoutes.post('/register', registerUser)
userRoutes.post('/login', loginUser)
userRoutes.get('/logout', logoutUser)
userRoutes.get('/get-user', protect, getUser)
userRoutes.patch('/update-user', protect, updateUser)
userRoutes.delete('/:id', protect, adminOnly, deleteUser)
userRoutes.get('/get-users', protect, subAdminOnly, getUsers)
userRoutes.get('/login-status', loginStatus)
userRoutes.post('/upgrade-user', protect, adminOnly, upgradeUser)
userRoutes.post('/send-email', protect, sendEmail)
userRoutes.post('/send-verification-email', protect, sendVerificationEmail)
userRoutes.patch('/verify-user/:verificationToken', verifyUser)
userRoutes.post('/forgot-password', forgotPassword)
userRoutes.put('/reset-password', resetPassword)

export default userRoutes
