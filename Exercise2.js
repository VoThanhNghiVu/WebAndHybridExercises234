/* Exercise 2: Create a new express based server, create one endpoint GET /posts into it and use
 JWT security scheme in your route to protect it.
The GET /posts should return an array of one line text messages such as “early bird catches the worm”.
You will need to create another route for sign in which is used to create the JWT. */

const express = require('express')
const jwt = require('jsonwebtoken');
const app = express()
const port = 3000

const secretKey = 'myjwtsecret' // Secret key for signing

app.use(express.json()) // Middleware to parse JSON bodies

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, secretKey, (err, payload) => {
      if (err) {
        return res.sendStatus(403); // Forbidden if token is invalid
      }
      req.user = payload;
      next();
    });
  } else {
    res.sendStatus(401); // Unauthorized if no token is provided
  }
};

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.post('/signin', (req, res) => {
  const user = { username: 'testUser' };

  // Sign the token with the user payload
  const token = jwt.sign({ user }, secretKey);

  // Return the token to the client
  res.json({ token });
});

// Protected route that requires a valid JWT
app.get('/posts', authenticateJWT, (req, res) => {
  res.json([
    "Early bird catches the worm",
    "Opportunity knocks but once",
    "Make hay while the sun shines"
  ]);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
