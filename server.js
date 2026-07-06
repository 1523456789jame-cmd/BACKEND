const express = require('express');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());

app.get('/', (req,res) => res.send("wm backend is running 🚀"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));