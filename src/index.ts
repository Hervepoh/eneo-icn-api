import express, { Express, NextFunction, Request, Response } from "express";
import { PORT } from "./secrets";
import rootRouter from "./routes";
import { PrismaClient } from "@prisma/client";
import { ErrorMiddleware } from "./middlewares/error";

const app: Express = express();

// Configure express behind a reverse proxy Express will trust the X-Forwarded-For and X-Forwarded-Proto headers
app.set('trust proxy', true);

// body parser
app.use(express.json());

app.use('/api/v1', rootRouter);

// unknow route
app.all("*", (req: Request, res: Response, next: NextFunction) => {
    const err = new Error(`Route ${req.originalUrl} not found`) as any;
    err.statusCode = 404;
    next(err);
});

// Capture Error
app.use(ErrorMiddleware);

app.listen(PORT, () => {
    console.log("App working...");
});