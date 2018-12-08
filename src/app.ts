import express from "express";
import compression from "compression";  // compresses requests
import session from "express-session";
import bodyParser from "body-parser";
import lusca from "lusca";
import dotenv from "dotenv";
import path from "path";
import mongoose from "mongoose";
import passport from "passport";
import expressValidator from "express-validator";

// Load environment variables from .env file, where API keys and passwords are configured
dotenv.config({ path: ".env" });

// Create Express server
const app = express();

// Connect to MongoDB
const mongoUrl = process.env.MONGODB_URI;
const mongoUrlDev = process.env.MONGODB_URI_LOCAL;
mongoose.Promise = global.Promise;
if (process.env.NODE_ENV === "development") {
  mongoose.connect(mongoUrl, { useMongoClient: true });
} else {
  mongoose.connect(mongoUrl, { useMongoClient: true });
}

// Express configuration
app.set("port", process.env.PORT || 3000);
app.use(compression());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressValidator());
app.use(passport.initialize());
app.use(passport.session());
app.use(lusca.xframe("SAMEORIGIN"));
app.use(lusca.xssProtection(true));

import { mainRoutes } from "./routes/mainRoutes";

app.use("/api/v1", mainRoutes);


export default app;