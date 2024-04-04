import express, { Request, Response, Express } from 'express';
import { PORT } from './secrets';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import rootRouter from './routes';
import { errorHandler } from './middlewares/errorMiddleware';
import { PrismaClient } from '@prisma/client';

const app:Express  = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(bodyParser.json());
app.use(
    cors({
      origin: [
        "http://localhost:3000", //nextjs
        "https://your-frontend-website.com",
      ],
    credentials: true
    })
);

export const prisma = new PrismaClient({
  // log:['query']
})

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World, from TypeScript Express Server!');
});

app.use('/api', rootRouter)

app.use(errorHandler)

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
