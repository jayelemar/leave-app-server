import { Router } from 'express'
import { getUser, loginUser, logoutUser, registerUser } from '../controllers/userControllers'
import { protect } from '../middlewares/authMiddleware'


const userRoutes:Router = Router()

userRoutes.post('/register', registerUser)
userRoutes.post('/login', loginUser)
userRoutes.get('/logout', logoutUser)
userRoutes.get('/getuser', protect, getUser)

export default userRoutes
