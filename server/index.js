import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import mongoSanitize from 'express-mongo-sanitize';
import connectDB from './config/db.js';
import { errorHandlerMiddelware } from './middleware/errorHandler.middleware.js';



import authRouter from './routes/auth.route.js';

dotenv.config();

connectDB();
const app = express();

const port = process.env.PORT || 5000;


app.use(cors())
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.urlencoded({extended:true}))

app.use(mongoSanitize());

app.use('/api/auth',authRouter);


app.use(errorHandlerMiddelware())
app.listen(port,()=>{
    console.log(`Server is running on port ${port}`);
})