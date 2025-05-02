require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

const expireTime = 1 * 60 * 60 * 1000; // 1 hour

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = require('/databaseConnection');

const userCollection = database.db(mongodb_database).collection('user');

app.use(express.urlencoded({ extended: true }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret,
    },
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
}));

app.get('/', (req, res) => {
    if (req.session.user) {
        res.send(`
            <h1>Hello, ${req.session.user.name}!</h1>
            <a href="/members">Go to Members Area</a><br>
            <a href="/logout">Logout</a>
        `);
    } else {
        res.send(`
            <h1>Welcome</h1>
            <a href="/signup">Sign Up</a><br>
            <a href="/login">Log In</a>
        `);
    }
});

app.get('/signup', (req, res) => {
    res.send(`
        create user
        <form action="/signupSubmit" method="POST">
            <input type="text" name="name" placeholder="name"><br>
            <input type="email" name="email" placeholder="email"><br>
            <input type="password" name="password" placeholder="password"><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    if (!name) {
        res.send(`
            <p>Name is required</p>
            <a href="/signup">Try again</a>
        `);
        return;
    }
    if (!email) {
        res.send(`
            <p>Email is required</p>
            <a href="/signup">Try again</a>
        `);
        return;
    }
    if (!password) {
        res.send(`
            <p>Password is required</p>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(5).max(50).required()
    });

    const validation = schema.validate({ name, email, password });
    if (validation.error != null) {
        res.send(`
            <h1 style='color: red;'>A NoSQL injection attack was detected!!</h1><br>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    const hashedPass = await bcrypt.hash(req.body.password, saltRounds);

    await userCollection.insertOne({
        name: req.body.name,
        email: req.body.email,
        password: hashedPass
    });

    req.session.user = { name, email };
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.send(`
        log in
        <form action="/loggingin" method="POST">
            <input type="email" name="email" placeholder="email"><br>
            <input type="password" name="password" placeholder="password"><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(5).max(50).required()
    });

    const validation = schema.validate({ email, password });
    if (validation.error != null) {
        res.send(`
            <h1 style='color: red;'>A NoSQL injection attack was detected!!</h1><br>
            <a href="/login">Try again</a>
        `);
        return;
    }

    const user = await db.collection('user').findOne({ email });
    if (!user) {
        res.send(`
          <p style="color: red;">Invalid email or password</p><br>
          <a href="/login">Try again</a>
      `);
        return;
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
        req.session.authenticated = true;
        req.session.cookie.maxAge = expireTime;
    } else {
        res.send(`
          <p style="color: red;">Invalid email or password</p><br>
          <a href="/login">Try again</a>
      `);
      return;
    }

    req.session.user = { name: user.name, email: user.email };
    res.redirect('/members');
});

app.get('/members', (req, res) => {
    if (!req.session.user) {
        res.redirect('/');
        return;
    }

    const images = ['cat1.webp', 'cat2.png', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.user.name}!</h1>
        <img src="/img/${randomImage}" alt="Random Image" style="max-width: 300px;">
        <br>
        <a href="/logout">Logout</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get("*dummy", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Server running on port " + port);
});