require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default || require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 12;

// MongoDB connection URI
const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;

// Connect to MongoDB
async function connectDB() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection("users");
  console.log("Connected to MongoDB!");
}
connectDB();

// Middleware setup
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: mongoUri,
      dbName: process.env.MONGODB_DATABASE,
      collectionName: "sessions",
      ttl: 60 * 60, // session expiration time in seconds (1 hour)
    }),
    cookie: { maxAge: 60 * 60 * 1000 }, // cookie expiration time (1 hour)
  }),
);

// Home route
app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Hello, ${req.session.user.name}!</h1>
      <a href="/members"><button>Go to Members Area</button></a><br><br>
      <a href="/logout"><button>Logout</button></a>
    `);
  } else {
    res.send(`
      <h1>Home</h1>
      <a href="/signup"><button>Sign up</button></a><br><br>
      <a href="/login"><button>Log in</button></a>
    `);
  }
});

// ========== Signup Page ==========
app.get("/signup", (req, res) => {
  res.send(`
    <h2>Create User</h2>
    <form action="/signupSubmit" method="POST">
      <input name="name" placeholder="name" required/><br>
      <input name="email" placeholder="email" required/><br>
      <input name="password" type="password" placeholder="password" required/><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

// ========== Signup Handler ==========
app.post("/signupSubmit", async (req, res) => {
  const { name, email, password } = req.body;

  // Basic input validation
  if (!name)
    return res.send('Name is required. <a href="/signup">Try again</a>');
  if (!email)
    return res.send('Email is required. <a href="/signup">Try again</a>');
  if (!password)
    return res.send('Password is required. <a href="/signup">Try again</a>');

  // Joi validation to prevent NoSQL injection
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
  });

  const { error } = schema.validate({ name, email, password });
  if (error)
    return res.send(
      `Invalid input: ${error.message} <a href="/signup">Try again</a>`,
    );

  // Hash password using bcrypt
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Store user in database
  await userCollection.insertOne({ name, email, password: hashedPassword });

  // Create session
  req.session.user = { name, email };
  res.redirect("/members");
});

// ========== Login Page ==========
app.get("/login", (req, res) => {
  res.send(`
    <h2>Log In</h2>
    <form action="/loginSubmit" method="POST">
      <input name="email" placeholder="email" required/><br>
      <input name="password" type="password" placeholder="password" required/><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

// ========== Login Handler ==========
app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;

  // Joi validation
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
  });

  const { error } = schema.validate({ email, password });
  if (error) return res.send(`Invalid input. <a href="/login">Try again</a>`);

  // Find user in database
  const user = await userCollection.findOne({ email });
  if (!user)
    return res.send(
      'Invalid email/password combination. <a href="/login">Try again</a>',
    );

  // Compare password
  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.send(
      'Invalid email/password combination. <a href="/login">Try again</a>',
    );

  // Create session
  req.session.user = { name: user.name, email: user.email };
  res.redirect("/members");
});

// ========== Members Page ==========
app.get("/members", (req, res) => {
  if (!req.session.user) return res.redirect("/");

  const images = ["puppy1.png", "puppy2.png", "puppy3.png"];
  const randomImg = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.user.name}.</h1>
    <img src="/${randomImg}" width="300"/><br><br>
    <a href="/logout"><button>Sign out</button></a>
  `);
});

// ========== Logout ==========
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// ========== 404 Handler ==========
app.use((req, res) => {
  res.status(404).send("<h1>Page not found - 404</h1>");
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
