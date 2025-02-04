require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const morgan = require('morgan');

const app = express();
const port = process.env.PORT || 3001;

const {
    DB_HOST,
    DB_USER,
    DB_PASS,
    DB_NAME,
    SESSION_SECRET,
    JWT_SECRET,
    NODE_ENV,
} = process.env;

// Create a Winston logger instance
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/server.log' })
    ]
});

// Use Morgan to log HTTP requests, and integrate with Winston
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// MySQL connection
const db = mysql.createConnection({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASS,
    database: DB_NAME
});

db.connect((err) => {
    if (err) {
        logger.error('Error connecting to the database:', err);
        return;
    }
    logger.info('Connected to database');
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set up session middleware with session expiration and secure cookies
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 30 * 60 * 1000, // Session expires in 30 minutes of inactivity
        secure: NODE_ENV === 'production' // Set secure to true in production
    }
}));

// Middleware to auto-logout users after session expiration
app.use((req, res, next) => {
    if (req.session) {
        // Reset the session expiration time on every request
        req.session._garbage = Date();
        req.session.touch();
    }
    next();
});

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting to login and signup routes
app.use('/login', limiter);
app.use('/signup', limiter);

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
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    const insertUserQuery = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)';

    db.query(checkUserQuery, [username], (err, results) => {
        if (err) {
            logger.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length > 0) {
            return res.status(400).send('Username already taken');
        } else {
            const role = (username === 'admin') ? 'admin' : 'user';
            db.query(insertUserQuery, [username, email, hashedPassword, role], (err, result) => {
                if (err) {
                    logger.error('Database error:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                return res.status(200).send('Registration successful');
            });
        }
    });
});

// Handle user login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ?';

    db.query(query, [username], async (err, results) => {
        if (err) {
            logger.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
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
                return res.redirect('/welcome');
            } else {
                return res.status(400).send('Invalid username or password');
            }
        } else {
            return res.status(400).send('Invalid username or password');
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
            logger.error('Error fetching user data:', err);
            return res.status(500).send('Server error');
        }
        res.json(results); // Return all non-admin users' data
    });
});

// Handle logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            logger.error('Failed to log out:', err);
            return res.status(500).send('Failed to log out');
        }
        res.status(200).send('Logged out');
    });
});

app.listen(port, () => {
    logger.info(`Server running at http://localhost:${port}`);
});
