const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

// const db = require('./database/dbConfig.js');
const Users = require('./users-model.js');

const server = express();

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

    if (username && password) {
        Users.findBy({ username })
            .first()
            .then(user => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    res.status(200).json({ message: `Welcome, ${user.username}.`});
                } else {
                    res.status(401).json({ message: 'You shan\'t pass!' });
                }
            })
            .catch(error => {
                res.status(500).json(error);
            });
    } else {
        res.status(400).json({ message: 'Please provide credentials' });
    }
});

server.get('/api/users', protected, (req, res) => {
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