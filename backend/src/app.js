import cors from "cors";
import express from "express";
import appRouter from "./routes/index.js";
import notFoundMiddleware from "./middlewares/not-found.middleware.js";
import errorMiddleware from "./middlewares/error.middleware.js";
import env from "./config/env.js";

const app = express();

app.use(express.json());
app.use(cors({ origin: env.clientUrl }));

app.use('/api/v1', appRouter);

app.use(notFoundMiddleware);
app.use(errorMiddleware);

export default app;
