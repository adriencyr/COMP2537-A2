const path = require("path");
const fs = require("fs");
const express = require("express");
const ejs = require("ejs");
const bcrypt = require("bcrypt");
const joi = require("joi");
const { MongoClient } = require("mongodb");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB setup
const mongoUrl = process.env.MONGODB_URI;

const client = new MongoClient(mongoUrl);

let userCollection;

async function connectToDatabase() {
    try {
        await client.connect();

        const db = client.db(process.env.MONGODB_DATABASE);
        userCollection = db.collection("users");

        console.log("Connected to MongoDB");
    } catch (err) {
        console.error("MongoDB connection error:", err);
        process.exit(1);
    }
}

// Joi validation
const signupSchema = joi.object({
    name: joi.string()
        .trim()
        .alphanum()
        .min(1)
        .max(30)
        .required()
        .messages({
            "string.empty": "Username is required",
            "any.required": "Username is required"
        }),

    email: joi.string()
        .trim()
        .email()
        .max(254)
        .required()
        .messages({
            "string.empty": "Email is required",
            "string.email": "Email must be valid",
            "string.max": "Email cannot be more than 254 characters",
            "any.required": "Email is required"
        }),

    password: joi.string()
        .min(8)
        .max(24)
        .required()
        .messages({
            "string.empty": "Password is required",
            "string.min": "Password must be at least 8 characters",
            "string.max": "Password cannot be more than 24 characters",
            "any.required": "Password is required"
        })
});

const loginSchema = joi.object({
    email: joi.string()
        .trim()
        .lowercase()
        .email()
        .max(254)
        .required()
        .messages({
            "string.empty": "Email is required",
            "string.email": "Email must be valid",
            "string.max": "Email cannot be more than 254 characters",
            "any.required": "Email is required"
        }),

    password: joi.string()
        .min(8)
        .max(24)
        .required()
        .messages({
            "string.empty": "Password is required",
            "string.min": "Password must be at least 8 characters",
            "string.max": "Password cannot be more than 24 characters",
            "any.required": "Password is required"
        })
});

// Helper functions
async function hashPassword(plainPassword) {
    const saltRounds = 10;
    return await bcrypt.hash(plainPassword, saltRounds);
}

// Main Logic
app.use(express.static(path.join(__dirname, "public"), {
    index: false
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs')

// Session setup
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: "sessions",
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    cookie: {
        maxAge: 60 * 60 * 1000 // 1 hour
    }
}));

app.get("/", (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/members");
        return;
    }

    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/signup", (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/members");
        return;
    }

    res.sendFile(path.join(__dirname, "signup.html"));
});

app.get("/login", (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/members");
        return;
    }

    res.sendFile(path.join(__dirname, "login.html"));
});

app.post("/signupSubmit", async (req, res) => {
    if (req.session.authenticated) {
        return res.redirect("/members");
    }

    const { error, value } = signupSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
    });

    if (error) {
        const errorMessages = error.details
            .map(detail => `<li>${detail.message}</li>`)
            .join("");

        return res.status(400).send(`
            <p>Signup failed:</p>
            <ul>${errorMessages}</ul>
            <p>Please <a href="/signup">try again.</a></p>
        `);
    }

    const { name, email, password } = value;

    try {
        const existingUser = await userCollection.findOne({ email: email });

        if (existingUser) {
            return res.status(400).send(`
                <p>An account with this email already exists.</p>
                <p>Please <a href="/signup">try again.</a></p>
            `);
        }

        const hashedPassword = await hashPassword(password);

        await userCollection.insertOne({
            name: name,
            email: email,
            password: hashedPassword
        });

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;

        res.redirect("/members");
    } catch (err) {
        console.error("Signup error:", err);

        res.status(500).send(`
            <p>Something went wrong while creating your account.</p>
            <p>Please <a href="/signup">try again.</a></p>
        `);
    }
});

app.post("/loginSubmit", async (req, res) => {
    if (req.session.authenticated) {
        return res.redirect("/members");
    }

    const { error, value } = loginSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
    });

    if (error) {
        const errorMessages = error.details
            .map(detail => `<li>${detail.message}</li>`)
            .join("");

        return res.status(400).send(`
            <p>Login failed:</p>
            <ul>${errorMessages}</ul>
            <p>Please <a href="/login">try again.</a></p>
        `);
    }

    const { email, password } = value;

    try {
        const existingUser = await userCollection.findOne({ email: email });

        if (!existingUser) {
            return res.status(400).send(`
                <p>Invalid email or password.</p>
                <p>Please <a href="/login">try again.</a></p>
            `);
        }

        const passwordMatches = await bcrypt.compare(password, existingUser.password);

        if (!passwordMatches) {
            return res.status(400).send(`
                <p>Invalid email or password.</p>
                <p>Please <a href="/login">try again.</a></p>
            `);
        }

        req.session.authenticated = true;
        req.session.name = existingUser.name;
        req.session.email = existingUser.email;

        req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).send("Could not save session.");
            }

            res.redirect("/members");
        });
    } catch (err) {
        console.error("Login error:", err);

        res.status(500).send(`
            <p>Something went wrong while logging in to your account.</p>
            <p>Please <a href="/login">try again.</a></p>
        `);
    }
});

app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/");
    }

    const imagesFolder = path.join(__dirname, "public");

    fs.readdir(imagesFolder, (err, files) => {
        if (err) {
            console.error("Image folder error:", err);
            return res.status(500).send("Could not load images.");
        }

        const imageList = files.filter(file => /\.(jpg|jpeg|png|gif)$/i.test(file));

        if (imageList.length === 0) {
            return res.status(500).send("No images found.");
        }

        const randomIndex = Math.floor(Math.random() * imageList.length);
        const selectedImage = imageList[randomIndex];

        res.render("members", {
            name: req.session.name,
            selectedImage: selectedImage
        });
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).send("Could not log out.");
        }

        res.redirect("/");
    });
});

app.use((req, res) => {
    res.status(404).send(`
        <h1>404</h1>
        <p>Page not found.</p>
        <p><a href="/">Return home</a></p>
    `);
});

// Database Connection
connectToDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is live: http://localhost:${PORT}/`);
    });
});