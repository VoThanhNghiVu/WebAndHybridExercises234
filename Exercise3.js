/*Exercise 3: 
Role-Based Access Control (RBAC) with JWT
Enhance the basic JWT authentication by assigning two roles (e.g., admin, user).
The GET /posts should be available to both user groups.
Create a new endpoint POST /posts, which is used to add new one line text messages to the service.
Only “admin” user should be allowed access.
Key Features:
    • Users receive a role upon login.
    • Middleware checks JWT and verifies if the user has the required role. */


const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

const JWT_SECRET = 'mysecretkey';

app.use(express.json());

let messages = [
    "Early bird catches the worm",
    "Opportunity knocks but once",
    "Make hay while the sun shines"
];

// Middleware check and validate JWT from Authorization header.
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Token is invalid or expired" });
      }
      req.user = user; //Save the token payload to request object
      next();
    });
  } else {
    res.status(401).json({ error: "Token not provided" });
  }
};

// Middleware checks role-based access
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      next();
    } else {
      res.status(403).json({ error: "You do not have permission to access this function." });
    }
  };
};

app.get('/', (req, res) => {
    res.send('Hello World!')
  })

// POST /signin (admin/user)
// Return a JWT token for the user
app.post('/signin', (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }
  
    if (username === 'admin' && password === 'adminpass') {
      const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET); // JWT with payload and secret key 
      return res.json({ token });
    } 
      else if (username === 'user' && password === 'userpass') {
          const token = jwt.sign({ username, role: 'user' }, JWT_SECRET, { expiresIn: '1h' });
      return res.json({ token });
    } 
      else {
      return res.status(401).json({ error: "Invalid login information" });
    }
  });
  

// GET /posts (This endpoint is protected by JWT but allows both user and admin)
app.get('/posts', authenticateJWT, (req, res) => {
  res.json(messages);
});

// POST /posts (This endpoint is protected by JWT and only allows admin)
app.post('/posts', authenticateJWT, authorizeRole('admin'), (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ error: "Please provide message information" });
  }
  posts.push(message);
  res.status(201).json({ message: "Post successful", messages });
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
