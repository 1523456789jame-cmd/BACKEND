const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database('./wm.db');
db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT)`);

app.get('/', (req,res) => res.send("wm backend is running "));

app.post('/signup', async (req,res) => {
  const {name, email, password} = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name,email,password) VALUES (?,?,?)', [name,email,hash], (err) => {
    if(err) return res.status(400).json({error: "Email already exists"});
    res.json({success: true, message: "Account created"});
  });
});

app.post('/login', (req,res) => {
  const {email, password} = req.body;
  db.get('SELECT * FROM users WHERE email =?', [email], async (err,row) => {
    if(!row) return res.status(400).json({error: "User not found"});
    const match = await bcrypt.compare(password, row.password);
    if(!match) return res.status(400).json({error: "Wrong password"});
    const token = jwt.sign({id: row.id}, "wmsecretkey");
    res.json({success: true, token});
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));