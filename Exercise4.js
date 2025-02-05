/* Exercise 4:
Refresh Tokens & Token Expiry Handling
Improve security by implementing refresh tokens to extend session validity without requiring frequent
logins. Refresh token is given along access token during sign in.
Key Features:
    • Access tokens have a short expiration time (e.g., 15 minutes).
    • A separate refresh token (longer lifespan) allows users to request a new access token.
    • Logout functionality to invalidate refresh tokens.
*/

const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const port = 3000;

app.use(express.json());

const JWT_SECRET = "access-token-secret"; // Secrets for signing token
const REFRESH_TOKEN_SECRET = "refresh-token-secret";

let refreshTokens = [];
const messages = [
  "Early bird catches the worm",
  "Opportunity knocks but once",
  "Make hay while the sun shines",
];

const users = [
  { username: "admin", password: "adminpass", role: "admin" },
  { username: "user", password: "userpass", role: "user" },
];

// Middleware to authenticate access tokens (JWT)
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    // Expected format: Bearer <token>
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res
          .status(403)
          .json({ error: "Invalid or expired access token" });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: "Access token is required" });
  }
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Logs in a user and returns an access token (15 minutes) and a refresh token
app.post("/signin", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const payload = { username: user.username, role: user.role }; // Create payload for JWT
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" }); // Create an access token (expires in 15 minutes)
  const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
    expiresIn: "4h",
  }); // Create a refresh token (expires in 4 hours)
  refreshTokens.push(refreshToken); // Store refresh token for later validation

  res.json({ accessToken, refreshToken });
});

app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token is required" });
  }

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    // Generate new access token using the payload from refresh token
    const payload = { username: user.username, role: user.role };
    const newAccessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });
    res.json({ accessToken: newAccessToken });
  });
});

// Returns an array of messages, accessible to all users with a valid access token
app.get("/posts", authenticateJWT, (req, res) => {
  res.json(messages);
});

// Middleware to authorize admin users.
const authorizeAdmin = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(403).json({ error: "Admin required" });
  }
};

// Allows an admin to add a new post
app.post("/posts", authenticateJWT, authorizeAdmin, (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: "Message is required" });
  }

  posts.push(message);
  res.status(201).json({ message: "Post added successfully", messages });
});

app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token is required" });
  }

  refreshTokens = refreshTokens.filter((token) => token !== refreshToken); // Remove the refresh token from our store
  res.json({ message: "Logged out successfully" });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
