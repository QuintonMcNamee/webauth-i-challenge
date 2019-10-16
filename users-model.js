const db = require('./database/dbConfig.js');

module.exports = {
    find,
    findBy,
    add,
    findById
};

function find() {
    return db('users').select('id', 'username', 'password');
};

function findBy(id) {
    return db('users').where(id);
};

function add(user) {
    return db('users')
        .insert(user, 'id')
        .then(ids => {
            const [id] = ids;
            return findById(id);
        });
};

function findById(id) {
    return db('users')
        .where({ id })
        .first();
};

