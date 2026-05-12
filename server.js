const path = require("path");
const fs = require("fs");
const express = require("express");
const ejs = require("ejs");
const bcrypt = require("bcrypt");
const joi = require("joi");
const { MongoClient, ObjectId } = require("mongodb");
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
app.set("view engine", "ejs");

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

app.use((req, res, next) => {
    res.locals.authenticated = req.session.authenticated;
    res.locals.name = req.session.name;
    res.locals.user_type = req.session.user_type || "user";
    next();
});

app.get("/", (req, res) => {
    if (req.session.authenticated) {
        return res.redirect("/members");
    }

    res.render("index", {
        title: "Home"
    });
});

app.get("/signup", (req, res) => {
    if (req.session.authenticated) {
        return res.redirect("/members");
    }

    res.render("signup", {
        title: "Sign Up"
    });
});

app.get("/login", (req, res) => {
    if (req.session.authenticated) {
        return res.redirect("/members");
    }

    res.render("login", {
        title: "Login"
    });
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
        const errorMessages = error.details.map(detail => detail.message);

        return res.status(400).render("error", {
            title: "Signup Failed",
            statusCode: 400,
            heading: "Signup failed",
            messages: errorMessages,
            message: null,
            returnUrl: "/signup",
            returnText: "Try again"
        });
    }

    const { name, email, password } = value;

    try {
        const existingUser = await userCollection.findOne({ email: email });

        if (existingUser) {
            return res.status(400).render("error", {
                title: "Signup Failed",
                statusCode: 400,
                heading: "Signup failed",
                message: "An account with this email already exists.",
                messages: null,
                returnUrl: "/signup",
                returnText: "Try again"
            });
        }

        const hashedPassword = await hashPassword(password);

        await userCollection.insertOne({
            name: name,
            email: email,
            password: hashedPassword,
            user_type: "user",
        });

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;
        req.session.user_type = "user";

        res.redirect("/members");
    } catch (err) {
        console.error("Signup error:", err);

        return res.status(500).render("error", {
            title: "Server Error",
            statusCode: 500,
            heading: "Something went wrong",
            message: "Something went wrong while creating your account.",
            messages: null,
            returnUrl: "/signup",
            returnText: "Try again"
        });
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
        const errorMessages = error.details.map(detail => detail.message);

        return res.status(400).render("error", {
            title: "Login Failed",
            statusCode: 400,
            heading: "Login failed",
            messages: errorMessages,
            message: null,
            returnUrl: "/login",
            returnText: "Try again"
        });
    }

    const { email, password } = value;

    try {
        const existingUser = await userCollection.findOne({ email: email });

        if (!existingUser) {
            return res.status(400).render("error", {
                title: "Login Failed",
                statusCode: 400,
                heading: "Login failed",
                message: "Invalid email or password.",
                messages: null,
                returnUrl: "/login",
                returnText: "Try again"
            });
        }

        const passwordMatches = await bcrypt.compare(password, existingUser.password);

        if (!passwordMatches) {
            return res.status(400).render("error", {
                title: "Login Failed",
                statusCode: 400,
                heading: "Login failed",
                message: "Invalid email or password.",
                messages: null,
                returnUrl: "/login",
                returnText: "Try again"
            });
        }

        req.session.authenticated = true;
        req.session.name = existingUser.name;
        req.session.email = existingUser.email;
        req.session.user_type = existingUser.user_type || "user";

        req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);

                return res.status(500).render("error", {
                    title: "Session Error",
                    statusCode: 500,
                    heading: "Could not save session",
                    message: "Something went wrong while saving your login session.",
                    messages: null,
                    returnUrl: "/login",
                    returnText: "Return to login"
                });
            }

            res.redirect("/members");
        });
    } catch (err) {
        console.error("Login error:", err);

        return res.status(500).render("error", {
            title: "Server Error",
            statusCode: 500,
            heading: "Something went wrong",
            message: "Something went wrong while logging in to your account.",
            messages: null,
            returnUrl: "/login",
            returnText: "Try again"
        });
    }
});

app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/");
    }

    const images = [
        "/1.jpg",
        "/2.jpg",
        "/3.jpg"
    ];

    res.render("members", {
        title: "Members",
        images: images
    });
});

app.get("/admin", async (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }

    if (req.session.user_type !== "admin") {
        return res.status(403).render("error", {
            title: "403",
            statusCode: 403,
            heading: "Not authorized",
            message: "You do not have permission to access this page.",
            messages: null,
            returnUrl: "/",
            returnText: "Return home"
        });
    }

    const users = await userCollection.find().toArray();

    res.render("admin", {
        title: "Admin",
        users: users
    });
});

app.get("/modifyMember/:userid", async (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }

    if (req.session.user_type !== "admin") {
        return res.status(403).render("error", {
            title: "403",
            statusCode: 403,
            heading: "Not authorized",
            message: "You do not have permission to access this page.",
            messages: null,
            returnUrl: "/",
            returnText: "Return home"
        });
    }

    const id = req.params.userid;

    if (!ObjectId.isValid(id)) {
        return res.status(400).render("error", {
            title: "Invalid User ID",
            statusCode: 400,
            heading: "Invalid user ID",
            message: "The provided user ID is not valid.",
            messages: null,
            returnUrl: "/admin",
            returnText: "Return to admin"
        });
    }

    const targetUser = await userCollection.findOne({
        _id: new ObjectId(id)
    });

    if (!targetUser) {
        return res.status(404).render("error", {
            title: "User Not Found",
            statusCode: 404,
            heading: "User not found",
            message: "No user exists with this ID.",
            messages: null,
            returnUrl: "/admin",
            returnText: "Return to admin"
        });
    }

    if (req.session.email === targetUser.email) {
        return res.status(403).render("error", {
            title: "403",
            statusCode: 403,
            heading: "Action not allowed",
            message: "You cannot promote or demote yourself.",
            messages: null,
            returnUrl: "/admin",
            returnText: "Return to admin"
        });
    }

    const currentType = targetUser.user_type || "user";
    const newType = currentType === "admin" ? "user" : "admin";

    await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { user_type: newType } }
    );

    res.redirect("/admin");
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);

            return res.status(500).render("error", {
                title: "Logout Error",
                statusCode: 500,
                heading: "Could not log out",
                message: "Something went wrong while ending your session.",
                messages: null,
                returnUrl: "/",
                returnText: "Return home"
            });
        }

        res.redirect("/");
    });
});

app.use((req, res) => {
    return res.status(404).render("error", {
        title: "404",
        statusCode: 404,
        heading: "Page not found",
        message: "The page you are looking for does not exist.",
        messages: null,
        returnUrl: "/",
        returnText: "Return home"
    });
});

// Database Connection
connectToDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is live: http://localhost:${PORT}/`);
    });
});