require('dotenv').config();

const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3001;

const {
    DB_HOST,
    DB_USER,
    DB_PASS,
    DB_NAME,
    SESSION_SECRET,
    JWT_SECRET,
} = process.env;

// MySQL connection
const db = mysql.createConnection({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASS,
    database: DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to database');
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set up session middleware
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // Session expires in 1 minute (adjust as needed)
}));

// Serve static files (except welcome.html)
app.use(express.static(path.join(__dirname, 'public')));

// Serve the index.html file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Middleware to check if user is logged in
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    } else {
        res.status(403).send('Please log in to access this page');
    }
};

// Middleware to verify JWT and check if the user is an admin
const verifyAdminJWT = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).send('Access denied. No token provided.');
    }

    jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send('Invalid token.');
        }

        if (decoded.role !== 'admin') {
            return res.status(403).send('Access denied. Admins only.');
        }

        req.user = decoded;
        next();
    });
};

// Handle user registration
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    const insertUserQuery = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)';

    db.query(checkUserQuery, [username], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            res.status(400).send('Username already taken');
        } else {
            const role = (username === 'admin') ? 'admin' : 'user';
            db.query(insertUserQuery, [username, email, hashedPassword, role], (err, result) => {
                if (err) throw err;
                res.status(200).send('Registration successful');
            });
        }
    });
});

// Handle user login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ?';

    db.query(query, [username], async (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            const passwordIsValid = await bcrypt.compare(password, user.password);
            if (passwordIsValid) {
                // Store user information in session
                req.session.user = { id: user.id, username: user.username, role: user.role };

                // If user is admin, generate JWT
                if (user.role === 'admin') {
                    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
                    return res.json({ message: 'Login successful', token });
                }

                // Redirect to /welcome after successful login
                res.redirect('/welcome');
            } else {
                res.status(400).send('Invalid username or password');
            }
        } else {
            res.status(400).send('Invalid username or password');
        }
    });
});

// Protect the welcome route
app.get('/welcome', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'protected', 'welcome.html'));
});

// Secure /api/users route
app.get('/api/users', verifyAdminJWT, (req, res) => {
    const query = 'SELECT id, username, email, role FROM users WHERE role != \'admin\'';

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching user data:', err);
            res.status(500).send('Server error');
            return;
        }
        res.json(results); // Return all non-admin users' data
    });
});

// Handle logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Failed to log out');
        }
        res.status(200).send('Logged out');
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
