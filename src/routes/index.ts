import { Router } from 'express'
import userRoutes from './userRoutes'
import mailRoutes from './mailRoutes'

const rootRouter: Router = Router()

rootRouter.use('/users', userRoutes)
rootRouter.use('/users', mailRoutes)

export default rootRouter
