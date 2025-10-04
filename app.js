const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/main', (req, res) => {
  res.json({ message: 'hello world' });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
