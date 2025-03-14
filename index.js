const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 8000;
app.use(express.json());
app.use(cors());

mongoose
  .connect(process.env.MONGO_URI, { dbName: "profileDB" })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Error:", err));

const userSchema = new mongoose.Schema(
  { email: String, password: String },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const generateAccessToken = (user) =>
  jwt.sign({ id: user._id, email: user.email }, "secret", { expiresIn: "30s" });

const generateRefreshToken = (user) =>
  jwt.sign({ id: user._id, email: user.email }, "refresh", {
    expiresIn: "10m",
  });

app.post("/auth/api/register", async (req, res) => {
  const { email, password } = req.body;
  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json("User already exists");
  const user = new User({ email, password });
  await user.save();
  res.json("User registered!");
});

app.post("/auth/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || user.password !== password) {
    return res.status(400).json("Invalid credentials");
  }
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  res.json({ accessToken, refreshToken });
});

app.post("/refresh/token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(refreshToken, "refresh", async (err, decoded) => {
    if (err) return res.status(403).json({ message: "Session Expired" });

    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.status(403).json({ message: "User not found" });

    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
  });
});

const authenticate = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Access Denied" });

  const token = authHeader.split(" ")[1]; // Extract the actual token
  try {
    const verified = jwt.verify(token, "secret");
    req.user = verified;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid Token" });
  }
};

app.get("/todos", authenticate, (req, res) => {
  res.json({ message: "Protected Data", user: req.user });
});

app.listen(PORT, () => {
  console.log(`Server Running on port ${PORT}`);
});
