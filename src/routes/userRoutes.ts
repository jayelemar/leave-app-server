import { Router } from 'express'
import { deleteUser, getUser, getUsers, loginStatus, loginUser, logoutUser, registerUser, sendEmail, updateUser, upgradeUser } from '../controllers/userControllers'
import { adminOnly, protect, subAdminOnly } from '../middlewares/authMiddleware'

const userRoutes:Router = Router()

userRoutes.post('/register', registerUser)
userRoutes.post('/login', loginUser)
userRoutes.get('/logout', logoutUser)
userRoutes.get('/getuser', protect, getUser)
userRoutes.patch('/updateuser', protect, updateUser)
userRoutes.delete('/:id', protect, adminOnly, deleteUser)
userRoutes.get('/getusers', protect, subAdminOnly, getUsers)
userRoutes.get('/loginstatus', loginStatus)
userRoutes.post('/upgradeuser', protect, adminOnly, upgradeUser)
userRoutes.post('/sendemail', protect, sendEmail)

export default userRoutes
