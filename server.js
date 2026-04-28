const path = require("path");
const express = require("express");

const app = express();
const PORT = 3000;

app.get('/', (res, req) => {
    req.sendFile(path.join(__dirname, "index.html"))
});

app.listen(PORT, () => {
    console.log(`Server is live: http://localhost:${PORT}/`)
});