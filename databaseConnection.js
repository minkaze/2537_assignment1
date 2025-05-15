const { MongoClient } = require('mongodb');
require('dotenv').config();

const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`;

const client = new MongoClient(mongoUrl);

let db = null;

async function connectToDatabase() {
    if (!db) {
        await client.connect();
        db = client.db(process.env.MONGODB_DATABASE);
    }
    return db;
}

module.exports = connectToDatabase;
