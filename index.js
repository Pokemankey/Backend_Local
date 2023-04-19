const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const uuid = require('uuid');
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        //console.log(file.filename);
        if (file.mimetype !== 'image/jpg' && file.mimetype !== 'image/png') {
            return cb(new Error('Only JPEG and PNG files are allowed'));
        }
        cb(null, true);
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const app = express();

const dbConfig = {
    host: process.env.AWS_DB_ENDPOINT,
    port: '3306',
    user: process.env.AWS_DB_USERNAME,
    password: process.env.AWS_DB_PASSWORD,
    database: 'mydatabase'
};

app.use(express.json());

app.get('/users', async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows, fields] = await connection.execute('SELECT * FROM users2');
        res.json(rows);
        await connection.end();
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

app.post('/users', upload.single('displayPic'), async (req, res) => {
    try {
        const imageName = uuid.v4();

        const uploadResult = await s3.upload({
            Bucket: 'amisportsimgs',
            Key: imageName,
            Body: req.file.buffer,
            ContentType: req.file.mimetype
        }).promise();

        // Save user data to database with S3 file URL
        const connection = await mysql.createConnection(dbConfig);
        const [result, fields] = await connection.execute(
            'INSERT INTO users (name, email, display_pic) VALUES (?, ?, ?)',
            [req.body.name, req.body.email, uploadResult.Location]
        );
        res.json({ id: result.insertId });
        await connection.end();
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

app.post('/register', async (req, res) => {
    try {
        console.log(req.body);
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
        const connection = await mysql.createConnection(dbConfig);
        const [result, fields] = await connection.execute(
            'INSERT INTO users (firstname, lastname, audNo, email, password, accesslevel) VALUES (?, ?, ?, ?, ?, ?)',
            [req.body.firstName, req.body.lastName, req.body.audNo, req.body.email, hashedPassword, 'student']
        );
        res.json({ success: true });
        await connection.end();
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

app.post('/login', async (req, res) => {
    try {
        if (!req.body.email || !req.body.password) {
            res.json({ success: false })
            return;
        }
        const { email, password } = req.body;
        const connection = await mysql.createConnection(dbConfig);
        const [result, fields] = await connection.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        rows = result[0];
        if (!rows) {
            res.json({ success: false })
            return;
        }
        const { firstname, accesslevel } = rows;
        const passwordMatch = await bcrypt.compare(password, rows.password);
        if (passwordMatch) {
            const user = { email, firstname, accesslevel };
            console.log(user);
            const accessToken = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '15m' });
            res.json({ accessToken, success: true });
        }
        else {
            res.json({ success: false });
        }
        await connection.end();
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

app.get('/protected', authenticateToken, (req, res) => {
    const accessToken = jwt.sign({ email: req.user.email, firstname: req.user.firstname, accesslevel: req.user.accesslevel }, process.env.JWT_SECRET, { expiresIn: '10s' });
    res.json({ message: 'Hello, ' + req.user.email, accessToken });
});

app.get('/newsfeed', authenticateToken, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [result, fields] = await connection.execute(
            'SELECT * FROM newsarticle'
        );
        rows = result;
        await connection.end();
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
    const accessToken = jwt.sign({ email: req.user.email, firstname: req.user.firstname, accesslevel: req.user.accesslevel }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ rows, accessToken });
});

// Start the server
app.listen(3000, () => {
    console.log('Server listening on port 3000');
});