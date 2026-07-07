const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database('./wm.db');
const SECRET = "wmsecretkey";

// ====== CREATE ALL TABLES ======
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    verified INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    content TEXT,
    imageUrl TEXT,
    likes INTEGER DEFAULT 0,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    postId INTEGER,
    UNIQUE(userId, postId)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    postId INTEGER,
    userId INTEGER,
    text TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    senderId INTEGER,
    receiverId INTEGER,
    text TEXT,
    read INTEGER DEFAULT 0,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    friendId INTEGER,
    status TEXT DEFAULT 'pending',
    UNIQUE(userId, friendId)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    text TEXT,
    read INTEGER DEFAULT 0,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ====== AUTH MIDDLEWARE ======
function auth(req, res, next){
  const token = req.headers.authorization?.split(" ")[1];
  if(!token) return res.status(401).json({success: false, error: "No token"});
  try{
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch{
    return res.status(401).json({success: false, error: "Invalid token"});
  }
}

// ====== AUTH ROUTES ======
app.post('/signup', async (req,res) => {
  const {name, email, password} = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name,email,password) VALUES (?,?,?)', [name,email,hash], (err) => {
    if(err) return res.status(400).json({success: false, error: "Email already exists"});
    res.json({success: true, message: "Account created"});
  });
});

app.post('/login', (req,res) => {
  const {email, password} = req.body;
  db.get('SELECT * FROM users WHERE email =?', [email], async (err,row) => {
    if(!row) return res.status(400).json({success: false, error: "User not found"});
    if(row.banned) return res.status(403).json({success: false, error: "Account banned"});
    const match = await bcrypt.compare(password, row.password);
    if(!match) return res.status(400).json({success: false, error: "Wrong password"});
    const token = jwt.sign({id: row.id}, SECRET);
    res.json({success: true, token, user: {id: row.id, name: row.name, verified: row.verified}});
  });
});

// ====== POSTS ======
app.post('/posts', auth, (req,res) => {
  const {content, imageUrl} = req.body;
  db.run('INSERT INTO posts (userId, content, imageUrl) VALUES (?,?,?)', [req.userId, content, imageUrl||""], function(err){
    if(err) return res.status(400).json({success: false, error: err.message});
    res.json({success: true, postId: this.lastID});
  });
});

app.get('/posts', auth, (req,res) => {
  db.all('SELECT p.*, u.name as author, u.verified FROM posts p JOIN users u ON p.userId = u.id ORDER BY p.createdAt DESC', (err,rows) => {
    res.json({success: true, posts: rows});
  });
});

// ====== LIKE ======
app.post('/posts/like', auth, (req,res) => {
  const {postId} = req.body;
  db.run('INSERT OR IGNORE INTO likes (userId, postId) VALUES (?,?)', [req.userId, postId], (err) => {
    db.run('UPDATE posts SET likes = likes + 1 WHERE id =?', [postId]);
    res.json({success: true});
  });
});

// ====== COMMENTS ======
app.post('/comments', auth, (req,res) => {
  const {postId, text} = req.body;
  db.run('INSERT INTO comments (postId, userId, text) VALUES (?,?,?)', [postId, req.userId, text], function(err){
    res.json({success: true});
  });
});

app.get('/comments/:postId', (req,res) => {
  db.all('SELECT c.*, u.name FROM comments c JOIN users u ON c.userId = u.id WHERE postId =? ORDER BY createdAt', [req.params.postId], (err,rows) => {
    res.json({success: true, comments: rows});
  });
});

// ====== MESSAGES ======
app.post('/messages', auth, (req,res) => {
  const {receiverId, text} = req.body;
  db.run('INSERT INTO messages (senderId, receiverId, text) VALUES (?,?,?)', [req.userId, receiverId, text], function(err){
    res.json({success: true});
  });
});

app.get('/messages/:userId', auth, (req,res) => {
  db.all('SELECT * FROM messages WHERE (senderId =? AND receiverId =?) OR (senderId =? AND receiverId =?) ORDER BY createdAt',
  [req.userId, req.params.userId, req.params.userId, req.userId], (err,rows) => {
    res.json({success: true, messages: rows});
  });
});

// ====== FRIENDS ======
app.post('/friend/request', auth, (req,res) => {
  const {friendId} = req.body;
  db.run('INSERT OR IGNORE INTO friends (userId, friendId, status) VALUES (?,?,?)', [req.userId, friendId, 'pending']);
  db.run('INSERT INTO notifications (userId, text) VALUES (?,?)', [friendId, 'Sent you a friend request']);
  res.json({success: true});
});

app.post('/friend/accept', auth, (req,res) => {
  const {friendId} = req.body;
  db.run('UPDATE friends SET status = "accepted" WHERE userId =? AND friendId =?', [friendId, req.userId]);
  db.run('INSERT OR IGNORE INTO friends (userId, friendId, status) VALUES (?,?,?)', [req.userId, friendId, 'accepted']);
  res.json({success: true});
});

app.get('/friends', auth, (req,res) => {
  db.all('SELECT f.*, u.name FROM friends f JOIN users u ON f.friendId = u.id WHERE f.userId =? AND f.status = "accepted"', [req.userId], (err,rows) => {
    res.json({success: true, friends: rows});
  });
});

// ====== NOTIFICATIONS ======
app.get('/notifications', auth, (req,res) => {
  db.all('SELECT * FROM notifications WHERE userId =? ORDER BY createdAt DESC', [req.userId], (err,rows) => {
    res.json({success: true, notifications: rows});
  });
});

app.post('/notifications/read', auth, (req,res) => {
  db.run('UPDATE notifications SET read = 1 WHERE userId =?', [req.userId]);
  res.json({success: true});
});

// ====== ADMIN ======
app.post('/admin/ban', auth, (req,res) => {
  const {userId} = req.body;
  db.run('UPDATE users SET banned = 1 WHERE id =?', [userId]);
  res.json({success: true, message: "User banned"});
});

app.post('/admin/verify', auth, (req,res) => {
  const {userId} = req.body;
  db.run('UPDATE users SET verified = 1 WHERE id =?', [userId]);
  res.json({success: true, message: "User verified"});
});

app.get('/', (req,res) => res.send("wm backend is running 🚀"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));