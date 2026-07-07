const express = require('express');
const cors = require('cors');
const { Server } = require("socket.io");
const http = require("http");
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// CONNECT TO RENDER POSTGRES
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// TEST ROUTE
app.get('/', (req, res) => res.send('WAPro Backend v652 Running 🔥'));

// REGISTER
app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  // we go add bcrypt + save to DB here
  res.json({ token: "demo_token_123", user: { name, email } });
});

// LOGIN
app.post('/login', async (req, res) => {
  res.json({ token: "demo_token_123", user: { name: "Gideon", email: "gideonadmin" } });
});

// REALTIME CHAT
io.on('connection', (socket) => {
  console.log('User connected');
  socket.on('send_message', (msg) => {
    io.emit('receive_message', msg);
  });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`Server on ${PORT}`));