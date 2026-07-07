const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors()); // NOTE: fine for token-auth (no cookies), but restrict `origin` to your real frontend domain in production

const db = new sqlite3.Database('./wm.db');

// SECRET must come from the environment. Never commit a real secret to source.
// Set JWT_SECRET in your environment before starting the server.
const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

// ====== CREATE ALL TABLES + ADD NEW COLUMNS ======
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    verified INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0,
    isAdmin INTEGER DEFAULT 0,
    bio TEXT DEFAULT "",
    avatar TEXT DEFAULT "",
    dob TEXT,
    gender TEXT,
    phone TEXT,
    location TEXT,
    photos TEXT
  )`);

  // Migration for existing DBs created before isAdmin existed.
  // SQLite errors if the column already exists — that's expected on repeat runs, safe to ignore.
  db.run(`ALTER TABLE users ADD COLUMN isAdmin INTEGER DEFAULT 0`, () => {});

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    content TEXT,
    imageUrl TEXT,
    location TEXT,
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

// ====== ADMIN MIDDLEWARE ======
// Always re-checks isAdmin against the DB (not the JWT payload), so revoking
// admin rights takes effect immediately instead of waiting for token expiry.
function admin(req, res, next){
  db.get('SELECT isAdmin, banned FROM users WHERE id =?', [req.userId], (err, row) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    if(!row || !row.isAdmin || row.banned) return res.status(403).json({success: false, error: "Admin only"});
    next();
  });
}

// ====== AUTH ROUTES ======
app.post('/signup', async (req,res) => {
  const {name, username, email, password, dob, gender, phone, location, photos} = req.body;

  if (!name || !username || !email || !password) {
    return res.status(400).json({success: false, error: "Missing required fields"});
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({success: false, error: "Password must be at least 8 characters"});
  }

  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name,username,email,password,dob,gender,phone,location,photos) VALUES (?,?,?,?,?,?,?,?,?)',
  [name,username,email,hash,dob,gender,phone,location,JSON.stringify(photos||[])], (err) => {
    if(err) return res.status(400).json({success: false, error: "Email/Username already exists"});
    res.json({success: true, message: "Account created"});
  });
});

app.post('/login', (req,res) => {
  const {email, password} = req.body;
  if (!email || !password) {
    return res.status(400).json({success: false, error: "Invalid credentials"});
  }

  db.get('SELECT * FROM users WHERE email =?', [email], async (err,row) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});

    // Generic message for both "no such user" and "wrong password" to prevent
    // attackers from using this endpoint to enumerate registered emails.
    if(!row) return res.status(400).json({success: false, error: "Invalid credentials"});

    const match = await bcrypt.compare(password, row.password);
    if(!match) return res.status(400).json({success: false, error: "Invalid credentials"});

    // Ban check happens only after password is confirmed correct, so a banned
    // account doesn't leak "this email exists" to someone who doesn't know the password.
    if(row.banned) return res.status(403).json({success: false, error: "Account banned"});

    const token = jwt.sign({id: row.id}, SECRET, {expiresIn: '7d'});

    // Minimal payload — anything sensitive (dob, phone, location, photos) is
    // fetched separately via GET /me, which requires auth and only returns
    // the caller's own data.
    res.json({
      success: true,
      token,
      user: {
        id: row.id,
        name: row.name,
        username: row.username,
        verified: row.verified,
        avatar: row.avatar,
        bio: row.bio
      }
    });
  });
});

app.get('/me', auth, (req,res) => {
  db.get('SELECT id, name, username, email, avatar, bio, dob, gender, phone, location, photos, isAdmin, banned FROM users WHERE id =?', [req.userId], (err,row) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    if(!row) return res.status(404).json({success: false});
    row.photos = row.photos? JSON.parse(row.photos) : [];
    res.json({success: true, user: row});
  });
});

// ====== POSTS ======
app.post('/posts', auth, (req,res) => {
  const {content, imageUrl, location} = req.body;
  if (!content && !imageUrl) {
    return res.status(400).json({success: false, error: "Post must have content or an image"});
  }
  db.run('INSERT INTO posts (userId, content, imageUrl, location) VALUES (?,?,?,?)',
  [req.userId, content||"", imageUrl||"", location||""], function(err){
    if(err) return res.status(400).json({success: false, error: err.message});
    res.json({success: true, postId: this.lastID});
  });
});

app.get('/posts', auth, (req,res) => {
  db.all('SELECT p.*, u.name as author, u.verified FROM posts p JOIN users u ON p.userId = u.id ORDER BY p.createdAt DESC', (err,rows) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, posts: rows});
  });
});

app.delete('/posts/:id', auth, (req,res) => {
  const postId = req.params.id;
  db.run('DELETE FROM posts WHERE id =? AND userId =?', [postId, req.userId], function(err){
    if(err) return res.status(500).json({success: false, error: "Server error"});
    if(this.changes === 0) return res.status(403).json({success: false, error: "Not allowed"});
    db.run('DELETE FROM comments WHERE postId =?', [postId]);
    db.run('DELETE FROM likes WHERE postId =?', [postId]);
    res.json({success: true, message: "Post deleted"});
  });
});

// ====== LIKE ======
app.post('/posts/like', auth, (req,res) => {
  const {postId} = req.body;
  if (!postId) return res.status(400).json({success: false, error: "postId required"});
  db.run('INSERT OR IGNORE INTO likes (userId, postId) VALUES (?,?)', [req.userId, postId], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    db.run('UPDATE posts SET likes = likes + 1 WHERE id =?', [postId]);
    db.run('INSERT INTO notifications (userId, text) SELECT userId, "liked your post" FROM posts WHERE id =?', [postId]);
    res.json({success: true});
  });
});

// ====== COMMENTS ======
app.post('/comments', auth, (req,res) => {
  const {postId, text} = req.body;
  if (!postId || !text) return res.status(400).json({success: false, error: "postId and text required"});
  db.run('INSERT INTO comments (postId, userId, text) VALUES (?,?,?)', [postId, req.userId, text], function(err){
    if(err) return res.status(500).json({success: false, error: "Server error"});
    db.run('INSERT INTO notifications (userId, text) SELECT userId, "commented on your post" FROM posts WHERE id =?', [postId]);
    res.json({success: true});
  });
});

app.get('/comments/:postId', (req,res) => {
  db.all('SELECT c.*, u.name FROM comments c JOIN users u ON c.userId = u.id WHERE postId =? ORDER BY createdAt', [req.params.postId], (err,rows) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, comments: rows});
  });
});

// ====== MESSAGES ======
app.post('/messages', auth, (req,res) => {
  const {receiverId, text} = req.body;
  if (!receiverId || !text) return res.status(400).json({success: false, error: "receiverId and text required"});
  db.run('INSERT INTO messages (senderId, receiverId, text) VALUES (?,?,?)', [req.userId, receiverId, text], function(err){
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true});
  });
});

app.get('/messages/:userId', auth, (req,res) => {
  db.all('SELECT * FROM messages WHERE (senderId =? AND receiverId =?) OR (senderId =? AND receiverId =?) ORDER BY createdAt',
  [req.userId, req.params.userId, req.params.userId, req.userId], (err,rows) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, messages: rows});
  });
});

// ====== FRIENDS ======
app.post('/friend/request', auth, (req,res) => {
  const {friendId} = req.body;
  if (!friendId) return res.status(400).json({success: false, error: "friendId required"});
  if (Number(friendId) === Number(req.userId)) return res.status(400).json({success: false, error: "Cannot friend yourself"});
  db.run('INSERT OR IGNORE INTO friends (userId, friendId, status) VALUES (?,?,?)', [req.userId, friendId, 'pending'], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    db.run('INSERT INTO notifications (userId, text) VALUES (?,?)', [friendId, 'Sent you a friend request']);
    res.json({success: true});
  });
});

app.post('/friend/accept', auth, (req,res) => {
  const {friendId} = req.body;
  if (!friendId) return res.status(400).json({success: false, error: "friendId required"});
  // Only accept if a pending request from friendId -> req.userId actually exists,
  // so a user can't unilaterally fabricate an "accepted" friendship.
  db.run('UPDATE friends SET status = "accepted" WHERE userId =? AND friendId =? AND status = "pending"', [friendId, req.userId], function(err){
    if(err) return res.status(500).json({success: false, error: "Server error"});
    if (this.changes === 0) return res.status(400).json({success: false, error: "No pending request from this user"});
    db.run('INSERT OR IGNORE INTO friends (userId, friendId, status) VALUES (?,?,?)', [req.userId, friendId, 'accepted']);
    res.json({success: true});
  });
});

app.get('/friends', auth, (req,res) => {
  db.all('SELECT f.*, u.name FROM friends f JOIN users u ON f.friendId = u.id WHERE f.userId =? AND f.status = "accepted"', [req.userId], (err,rows) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, friends: rows});
  });
});

// ====== NOTIFICATIONS ======
app.get('/notifications', auth, (req,res) => {
  db.all('SELECT * FROM notifications WHERE userId =? ORDER BY createdAt DESC', [req.userId], (err,rows) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, notifications: rows});
  });
});

app.post('/notifications/read', auth, (req,res) => {
  db.run('UPDATE notifications SET read = 1 WHERE userId =?', [req.userId], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true});
  });
});

// ====== ADMIN: BAN/VERIFY/UNBAN/UNVERIFY ======
// All admin routes require `auth` (valid token) AND `admin` (isAdmin=1 in DB).
app.post('/admin/ban', auth, admin, (req,res) => {
  const {userId} = req.body;
  if (!userId) return res.status(400).json({success: false, error: "userId required"});
  db.run('UPDATE users SET banned = 1 WHERE id =?', [userId], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, message: "User banned"});
  });
});

app.post('/admin/unban', auth, admin, (req,res) => {
  const {userId} = req.body;
  if (!userId) return res.status(400).json({success: false, error: "userId required"});
  db.run('UPDATE users SET banned = 0 WHERE id =?', [userId], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, message: "User unbanned"});
  });
});

app.post('/admin/verify', auth, admin, (req,res) => {
  const {userId} = req.body;
  if (!userId) return res.status(400).json({success: false, error: "userId required"});
  db.run('UPDATE users SET verified = 1 WHERE id =?', [userId], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, message: "User verified"});
  });
});

app.post('/admin/unverify', auth, admin, (req,res) => {
  const {userId} = req.body;
  if (!userId) return res.status(400).json({success: false, error: "userId required"});
  db.run('UPDATE users SET verified = 0 WHERE id =?', [userId], (err) => {
    if(err) return res.status(500).json({success: false, error: "Server error"});
    res.json({success: true, message: "User unverified"});
  });
});

// ====== PROFILE EDIT ======
app.post('/profile/update', auth, (req,res) => {
  const {name, username, bio, avatar, dob, gender, phone, location, photos} = req.body;
  db.run(`UPDATE users SET name=?, username=?, bio=?, avatar=?, dob=?, gender=?, phone=?, location=?, photos=? WHERE id=?`,
  [name, username, bio, avatar, dob, gender, phone, location, JSON.stringify(photos||[]), req.userId], (err) => {
    if(err) return res.status(400).json({success: false, error: err.message});
    res.json({success: true, message: "Profile updated"});
  });
});

app.get('/', (req,res) => res.send("wm backend is running "));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
