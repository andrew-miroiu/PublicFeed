const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
require("dotenv").config();

console.log("✅ Loaded ENV:", process.env.DATABASE_URL ? "OK" : "MISSING");

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Express app setup
const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || "fallbacksecret",
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

app.use((req, res, next) => {
  console.log("SESSION:", req.session);
  console.log("REQ.USER:", req.user);
  next();
});


// Passport local strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      const user = rows[0];

      if (!user) return done(null, false, { message: "Incorrect username" });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return done(null, false, { message: "Incorrect password" });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.username); // use username as identifier
});

passport.deserializeUser(async (username, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    done(null, rows[0]);
  } catch (err) {
    done(err);
  }
});

// Routes
app.get("/", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT messages.id, messages.title, messages.text, users.username 
       FROM messages 
       JOIN users ON messages.user_username = users.username
       ORDER BY messages.timestamp ASC`
    );
    const messages = result.rows;
    res.render("index", { user: req.user, messages });
  } catch (err) {
    console.error(err);
    res.send("Error retrieving messages");
  }
});


app.get("/sign-up", (req, res) => res.render("sign-up"));
app.post("/sign-up", async (req, res, next) => {
  try {
    const { first_name, last_name, username, password, confirmPassword } = req.body;

    if (!first_name || !last_name || !username || !password || !confirmPassword) {
      return res.send("All fields are required");
    }

    if (password !== confirmPassword) {
      return res.send("Passwords do not match");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, first_name, last_name, password) VALUES ($1, $2, $3, $4)",
      [username, first_name, last_name, hashedPassword]
    );

    res.redirect("/log-in");
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.get("/log-in", (req, res) => res.render("log-in"));
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/log-in"
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/log-in");
  });
});

// ====== post message ====== 

app.get("/createMessage", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  res.render("createMessage", { user: req.user });
});

app.post("/createMessage", async (req, res, next) => {
  if (!req.isAuthenticated()) return res.redirect("/log-in");

  const { title, message } = req.body;
  if (!title || !message) return res.send("Title and message are required");

  try {
    await pool.query(
      "INSERT INTO messages (title, text, user_username) VALUES ($1, $2, $3)",
      [title, message, req.user.username]
    );
    res.redirect("/");
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.post("/become-admin", async (req, res, next) => {
  const { adminPassword } = req.body;
  const hardcodedAdminPassword = "admin"; // Replace with a secure method in production

  // Make sure the user is logged in
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }

  if (adminPassword === hardcodedAdminPassword) {
    try {
      // Update the logged-in user's admin flag in DB
      await pool.query(
        "UPDATE users SET admin = true WHERE username = $1",
        [req.user.username]
      );
      req.user.admin = true;

      res.redirect("/");
    } catch (err) {
      console.error(err);
      next(err);
    }
  } else {
    res.send("Incorrect admin password");
  }
});


// Delete message route
app.post("/deleteMessage", async (req, res, next) => {
  if (!req.isAuthenticated() || !req.user.admin) {
    return res.status(403).send("Forbidden");
  }

  const { messageId } = req.body;
  console.log("Message ID received:", messageId);

  if (!messageId) {
    return res.status(400).send("No message ID provided");
  }

  try {
    await pool.query("DELETE FROM messages WHERE id = $1", [messageId]);
    res.redirect("/");
  } catch (err) {
    console.error(err);
    next(err);
  }
});

// Start server
app.listen(3000, () => {
  console.log("Server running: http://localhost:3000");
});
