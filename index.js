const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const sessions = require('express-session');
const KnexSessionStore = require('connect-session-knex')(sessions);

const db = require('./database/dbConfig.js');
const Users = require('./users-model.js');

const server = express();

const sessionConfiguration = {
    name: 'ohfosho',
    secret: 'keep it secret, keep it safe!',
    cookie: {
        httpOnly: true,
        maxAge: 1000 * 60 * 60,
        secure: false,
    },
    resave: false,
    saveUninitialized: true,

    store: new KnexSessionStore({
        knex: db,
        createtable: true,
        clearInterval: 1000 * 60 * 30,
    }),
};

server.use(sessions(sessionConfiguration));

server.use(helmet());
server.use(express.json());

const port = 5000;

server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.get('/', (req, res) => {
    res.send('It\'s alive!');
});

// custom middleware

function protected(req, res, next) {
    let { username, password } = req.headers;

    if (username && password) {
        Users.findBy({ username })
            .first()
            .then(user => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    next();
                } else {
                    res.status(401).json({ message: 'You shall not pass!' });
                }
            })
            .catch(error => {
                res.status(500).json(error);
            });
    } else {
        res.status(400).json({ message: 'Please provide credentials' });
    }
};

server.post('/api/register', (req, res) => {
    let user = req.body;

    const hash = bcrypt.hashSync(user.password, 8);

    user.password = hash;

    Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

server.post('/api/login', (req, res) => {
    let {username, password} = req.body;

    console.log('session', req.session);

    Users.findBy({ username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                req.session.username = user.username;

                console.log('session', req.session);
                res.status(200).json({
                    message: `Welcome ${user.username}!`,
                });
            } else {
                res.status(401).json({ message: 'Invalid Credentials' });
            }
        })
        .catch(error => {
            res.status(500).json(error);
        });

    // if (username && password) {
    //     Users.findBy({ username })
    //         .first()
    //         .then(user => {
    //             if (user && bcrypt.compareSync(password, user.password)) {
    //                 res.status(200).json({ message: `Welcome, ${user.username}.`});
    //             } else {
    //                 res.status(401).json({ message: 'You shan\'t pass!' });
    //             }
    //         })
    //         .catch(error => {
    //             res.status(500).json(error);
    //         });
    // } else {
    //     res.status(400).json({ message: 'Please provide credentials' });
    // }
});

server.get('/api/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(error => {
            res
                .status(200)
                .json({
                    message:
                        'You can check out any time you like, but you can never leave!',
                });
        });
    } else {
        res.status(200).json({ message: 'Already logged out' });
    }
});

server.get('/api/users', protected, (req, res) => {
    console.log('username', req.session.username);
    Users.find()
        .then(users => {
            res.json(users);
        })
        .catch(error => {
            res.send(error);
        });
});

server.get('/hash', (req, res) => {
    const password = req.headers.authorization;

    if (password) {
        const hash = bcrypt.hashSync(password, 8);

        res.status(200).json({ hash });
    } else {
        res.status(400).json({ message: 'Please provide credentials' });
    }
});