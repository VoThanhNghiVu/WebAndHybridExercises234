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
const passport = require("passport");
const BasicStrategy = require("passport-http").BasicStrategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken");

const app = express();
const port = 3000;

app.use(express.json());

const ACCESS_TOKEN_SECRET = "access-token-secret"; // Secrets for tokens
const REFRESH_TOKEN_SECRET = "refresh-token-secret";

const ACCESS_TOKEN_LIFETIME = "15m"; // Token lifetimes 15 minutes
const REFRESH_TOKEN_LIFETIME = "1d";

let refreshTokens = [];

const users = [
  { username: "admin", password: "adminpass", role: "admin" },
  { username: "user", password: "userpass", role: "user" },
];

const messages = [
  "Early bird catches the worm",
  "Opportunity knocks but once",
  "Make hay while the sun shines",
];

passport.use(
  new BasicStrategy((username, password, done) => {
    const user = users.find(
      (u) => u.username === username && u.password === password
    ); // Find user with matching credentials
    if (!user) {
      return done(null, false);
    }
    return done(null, user);
  })
);

// JWT Strategy for protecting endpoints
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // expects "Bearer <token>"
  secretOrKey: ACCESS_TOKEN_SECRET,
};

passport.use(
  new JwtStrategy(jwtOptions, (payload, done) => {
    console.log(payload);
    return done(null, payload);
  })
);

app.use(passport.initialize());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.post(
  "/signin",
  passport.authenticate("basic", { session: false }),
  (req, res) => {
    const payload = { username: req.user.username, role: req.user.role };

    const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
      expiresIn: ACCESS_TOKEN_LIFETIME,
    });
    const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
      expiresIn: REFRESH_TOKEN_LIFETIME,
    });

    refreshTokens.push(refreshToken); // Store refresh token for later validation/invalidation

    res.json({ accessToken, refreshToken });
  }
);

// refresh token, verifies and issues a new access token
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
    const payload = { username: user.username, role: user.role };
    const newAccessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
      expiresIn: ACCESS_TOKEN_LIFETIME,
    });
    res.json({ accessToken: newAccessToken });
  });
});

// Accessible to both admin and regular users
app.get(
  "/posts",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    console.log(req.user); // Access the decoded JWT payload
    res.json(messages);
  }
);

// Accessible only to admin
app.post(
  "/posts",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }
    messages.push(message);
    res.status(201).json({ message: "Post added successfully", messages });
  }
);

app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token is required" });
  }
  refreshTokens += ""; // Remove the token from memory store
  res.json({ message: "Logged out successfully" });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
