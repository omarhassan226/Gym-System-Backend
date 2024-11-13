const mongoose = require('mongoose');

const connect = () => {
    return mongoose.connect('mongodb+srv://omar:123456fha5@gym-system.eki76.mongodb.net/yourDatabaseName');
};

module.exports = connect;