const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

dotenv.config();
const app = express();

// ミドルウェア
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(cookieParser()); // 必ずルートの前に記述

// データベース接続
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            password TEXT NOT NULL,
            username TEXT,
            additionalData TEXT
        )`);
    }
});

// トークン生成
function generateToken(userId) {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

// トークン認証ミドルウェア
function authenticateToken(req, res, next) {
    const token = req.cookies ? req.cookies.auth_token : null;

    if (!token) {
        console.error('No auth_token found in cookies.');
        return res.status(401).send('Access Denied. Please log in.');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Invalid auth_token:', err.message);
            return res.status(403).send('Invalid Token.');
        }

        req.user = user;
        next();
    });
}

// ルート
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// ダッシュボードルート
app.get('/dashboard', authenticateToken, (req, res) => {
    const userId = req.user.id;

    // ユーザー情報をデータベースから取得
    db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error('Error fetching user data:', err);
            return res.status(500).send('Server error.');
        }

        if (!user) {
            return res.status(404).send('User not found.');
        }

        // ダッシュボードに必要なデータを渡す
        res.render('dashboard', {
            userId: user.id,
            username: user.username || `User-${user.id}`,
            additionalData: user.additionalData || 'No additional data available.',
        });
    });
});

// ログアウトルート
app.get('/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.redirect('/');
});

// 登録ルート
app.post('/register', async (req, res) => {
    const { id, password } = req.body;

    const username = `User-${id}`; // デフォルトのユーザー名
    const additionalData = `Welcome, User-${id}! This is your personalized dashboard.`; // 独自データ

    if (!id || !password || id.length !== 7 || isNaN(id)) {
        return res.status(400).send('A valid 7-digit ID and password are required.');
    }

    db.get(`SELECT * FROM users WHERE id = ?`, [id], async (err, user) => {
        if (err) return res.status(500).send('Server error.');
        if (user) return res.status(400).send('ID already exists.');

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (id, password, username, additionalData) VALUES (?, ?, ?, ?)`,
            [id, hashedPassword, username, additionalData],
            (err) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).send('Error registering user.');
                }
                res.status(201).send('User registered successfully!');
            }
        );
    });
});

// ログインルート
app.post('/login', (req, res) => {
    const { id, password } = req.body;

    db.get(`SELECT * FROM users WHERE id = ?`, [id], async (err, user) => {
        if (err) return res.status(500).send('Server error.');
        if (!user) return res.status(400).send('Invalid ID or password.');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid ID or password.');

        const token = generateToken(user.id);
        res.cookie('auth_token', token, { httpOnly: true }).redirect('/dashboard');
    });
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
