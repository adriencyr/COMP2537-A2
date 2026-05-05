const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const joi = require("joi");

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

const app = express();
const PORT = 3000;

// Helper functions
async function hashPassword(plainPassword) {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);

    return hashedPassword;
}

// Main Logic
app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (res, req) => {
    req.sendFile(path.join(__dirname, "index.html"))
});

app.get('/signup', (res, req) => {
    req.sendFile(path.join(__dirname, "signup.html"))
});

app.post("/signupSubmit", async (req, res) => {
    const { error, value } = signupSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
    });

    if (error) {
        const errorMessages = error.details.map(detail => `<li>${detail.message}</li>`).join("");

        return res.status(400).send(`
            <p>Signup failed:</p>
            <ul>${errorMessages}</ul>
            <p>Please <a href="/signup">try again.</a></p>
        `);
    }

    const { name, email, password } = value;

    const hashedPassword = await bcrypt.hash(password, 10);

    console.log("Username:", name);
    console.log("Email:", email);
    console.log("Hashed password:", hashedPassword);

    res.redirect("/");
});

app.listen(PORT, () => {
    console.log(`Server is live: http://localhost:${PORT}/`)
});