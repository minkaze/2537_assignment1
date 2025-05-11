require('./utils.js');

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

var { database } = include('/databaseConnection');

const userCollection = database.db(mongodb_database).collection('user');

app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime }
}));

const signupSchema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
});

function isAuthenticated(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

function isAdmin(req, res, next) {
    if (req.session.user.user_type != 'admin') {
        return res.status(403).render('403', { user: req.session.user });
    }
    next();
}

app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});

app.get('/signup', (req, res) => {
    res.render('signup', { error: null, user: req.session.user });
});

app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name) {
        return res.render('signup', { error: 'Name is required', user: req.session.user });
    }
    if (!email) {
        return res.render('signup', { error: 'Email is required', user: req.session.user });
    }
    if (!password) {
        return res.render('signup', { error: 'Password is required', user: req.session.user });
    }

    const { error } = signupSchema.validate({ name, email, password });
    if (error) {
        return res.render('signup', { error: 'A NoSQL injection attack was detected!!', user: req.session.user });
    }

    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
        return res.render('signup', { error: 'Email already exists', user: req.session.user });
    }

    const hashedPass = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name,
        email,
        password: hashedPass,
        user_type: 'user',
    });

    req.session.user = { name, email, user_type: 'user' };
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null, user: req.session.user });
});

app.post('/loggingin', async (req, res) => {
    const { email, password } = req.body;

    const { error } = loginSchema.validate({ email, password });
    if (error) {
        return res.render('login', { error: 'A NoSQL injection attack was detected!!', user: req.session.user });
    }

    const user = await userCollection.findOne({ email });
    if (!user) {
        return res.render('login', { error: 'Invalid email or password', user: req.session.user });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.render('login', { error: 'Invalid email or password', user: req.session.user });
    }

    req.session.user = {
        name: user.name,
        email: user.email,
        user_type: user.user_type || 'user',
    };
    res.redirect('/members');
});

app.get('/members', isAuthenticated, (req, res) => {
    const images = ['cat1.webp', 'cat2.png', 'cat3.jpg'];
    res.render('members', { user: req.session.user, images });
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    const users = await userCollection.find().toArray();
    res.render('admin', { user: req.session.user, users });
});

app.get('/promote/:email', isAuthenticated, isAdmin, async (req, res) => {
    const { email } = req.params;
    const { error } = Joi.string().email().required().validate(email);
    if (error) {
        return res.redirect('/admin');
    }
    try {
        await userCollection.updateOne(
            { email },
            { $set: { user_type: 'admin' } }
        );
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin');
    }
});

app.get('/demote/:email', isAuthenticated, isAdmin, async (req, res) => {
    const { email } = req.params;
    const { error } = Joi.string().email().required().validate(email);
    if (error) {
        return res.redirect('/admin');
    }
    try {
        await userCollection.updateOne(
            { email },
            { $set: { user_type: 'user' } }
        );
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin');
    }
});

app.get('/logout', isAuthenticated, (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.use((req, res) => {
    res.status(404).render('404', { user: req.session.user });
});

app.listen(port, () => {
    console.log('Server running on port ' + port);
});