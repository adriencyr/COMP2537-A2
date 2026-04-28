const path = require("path");
const express = require("express");

const app = express();
const PORT = 3000;

app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (res, req) => {
    req.sendFile(path.join(__dirname, "index.html"))
});

app.get('/signup', (res, req) => {
    req.sendFile(path.join(__dirname, "signup.html"))
});

app.post('/signupSubmit', (req, res) => {
    const username = req.body.name;

    if (username.length <= 0) {
        res.send(`
            <p>Username is missing, please <a href="/signup">try again.</a></p>
        `);
        return;
    }

    res.redirect("/");
});

app.listen(PORT, () => {
    console.log(`Server is live: http://localhost:${PORT}/`)
});