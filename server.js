const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const joi = require("joi");
const { MongoClient } = require("mongodb");
const dns = require("dns");

dns.setDefaultResultOrder("ipv4first");

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
        .required()
        .messages({
            "string.empty": "Email is required",
            "string.email": "Email must be valid",
            "any.required": "Email is required"
        }),

    password: joi.string()
        .min(8)
        .max(72)
        .required()
        .messages({
            "string.empty": "Password is required",
            "string.min": "Password must be at least 8 characters",
            "string.max": "Password cannot be more than 72 characters",
            "any.required": "Password is required"
        })
});

// Helper functions
async function hashPassword(plainPassword) {
    const saltRounds = 10;
    return await bcrypt.hash(plainPassword, saltRounds);
}

// Main Logic
app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/signup", (req, res) => {
    res.sendFile(path.join(__dirname, "signup.html"));
});

app.post("/signupSubmit", async (req, res) => {
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

        res.redirect("/");
    } catch (err) {
        console.error("Signup error:", err);

        res.status(500).send(`
            <p>Something went wrong while creating your account.</p>
            <p>Please <a href="/signup">try again.</a></p>
        `);
    }
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