import { Router } from 'express'
import { adminOnly, protect, subAdminOnly } from '../middlewares/authMiddleware'
import {
  changePassword,
  deleteUser,
  forgotPassword,
  getUser,
  getUsers,
  loginStatus,
  loginUser,
  loginWithCode,
  logoutUser,
  registerUser,
  resetPassword,
  updateUser,
  upgradeUser,
  verifyUser,
} from '../controllers/user'

const userRoutes: Router = Router()

userRoutes.post('/register', registerUser)
userRoutes.post('/login', loginUser)
userRoutes.get('/logout', logoutUser)
userRoutes.get('/get-user', protect, getUser)
userRoutes.patch('/update-user', protect, updateUser)
userRoutes.delete('/:id', protect, adminOnly, deleteUser)
userRoutes.get('/get-users', protect, subAdminOnly, getUsers)
userRoutes.get('/login-status', loginStatus)
userRoutes.post('/upgrade-user', protect, adminOnly, upgradeUser)
userRoutes.patch('/verify-user/:verificationToken', verifyUser)
userRoutes.post('/forgot-password', forgotPassword)
userRoutes.put('/reset-password/:resetToken', resetPassword)
userRoutes.patch('/change-password', protect, changePassword)
userRoutes.post('/login-with-code/:email', loginWithCode)

export default userRoutes
