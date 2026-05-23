const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'teamsync_secret_key_2025';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Database setup
const db = new sqlite3.Database('./teamsync.db');

// Create tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            storage_used INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            type TEXT,
            path TEXT NOT NULL,
            user_id INTEGER,
            folder_id INTEGER,
            is_starred BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            parent_id INTEGER,
            user_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    const demoPassword = bcrypt.hashSync('demo123', 10);

    db.run("INSERT OR IGNORE INTO users (id, email, password, name, storage_used) VALUES (1, 'alice@team.io', ?, 'Alice Johnson', 51200000000)", [demoPassword]);
});

// Multer configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Register
app.post('/api/register', (req, res) => {
    const { email, password, name } = req.body;

    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(
        'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
        [email, hashedPassword, name || email.split('@')[0]],
        function(err) {
            if (err) {
                return res.status(400).json({ error: 'User already exists' });
            }
            res.json({ message: 'User created successfully' });
        }
    );
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name
                }
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// Stats
app.get('/api/user/stats', authenticateToken, (req, res) => {
    db.get(
        'SELECT storage_used FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            db.get(
                'SELECT COUNT(*) as count FROM files WHERE user_id = ?',
                [req.user.id],
                (err, fileCount) => {
                    res.json({
                        storage_used: user?.storage_used || 0,
                        file_count: fileCount?.count || 0
                    });
                }
            );
        }
    );
});

// Files
app.get('/api/files', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC',
        [req.user.id],
        (err, files) => {
            res.json(files || []);
        }
    );
});

// Upload
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    db.run(
        `INSERT INTO files (filename, original_name, size, type, path, user_id)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
            req.file.filename,
            req.file.originalname,
            req.file.size,
            req.file.mimetype,
            req.file.path,
            req.user.id
        ],
        function(err) {
            if (err) {
                return res.status(400).json({ error: 'Failed to save file' });
            }

            res.json({
                id: this.lastID,
                filename: req.file.filename,
                original_name: req.file.originalname
            });
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
