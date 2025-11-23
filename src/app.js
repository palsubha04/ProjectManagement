import express from "express";
import cors from "cors";

const app = express();

// Middleware to parse JSON and URL-encoded data with a size limit
// and serve static files from the "public" directory
// Adjust the size limit as needed
// Basic Configuration
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

// Enable CORS for all routes
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// import the routes
import healthcheckRoutes from "./routes/healthcheck.routes.js";

// use the routes
app.use("/api/v1/healthcheck", healthcheckRoutes);

app.get("/", (req, res) => {
  res.send("Hello World! Welcome to the Base Campy API.");
});

export default app;
