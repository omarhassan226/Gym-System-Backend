const express = require("express");
const app = express();
const connect = require('./config/connection');
const router = require('./routes/routes')
const cors = require('cors')
const cookieParser = require("cookie-parser");

const port = 3000;

app.use(express.json())
app.use(cookieParser())
app.use(cors(
    { credentials: true },
    ['http://localhost:3000']
))
app.use('/api', router)

connect()
    .then(() => {
        if (connect) {
            console.log('Database Connection Started!');
        }
        app.listen(port, () => {
            console.log(`Server is Running on port ${port}`);
        });
    })
    .catch((err) => {
        console.log("Database connection error:", err);
    });