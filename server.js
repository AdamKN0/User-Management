const express = require('express');
const dotenv = require('dotenv');
const validator = require('validator');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || 'localhost';
const DB_F = path.join(__dirname, 'db.json');

const read_db = () => JSON.parse(fs.readFileSync(DB_F, 'utf8'));
const write_db = data => fs.writeFileSync(DB_F, JSON.stringify(data, null, 2));

if (!fs.existsSync(DB_F))
    write_db([]);

const isValidName = name => {
    if (!name || typeof name !== 'string')
        return "Please provide your name.";
    const trimmed = validator.trim(name);
    if (!validator.isLength(trimmed, { min: 3, max: 50 }))
        return "Name should be between 3 and 50 characters.";
    const cleaned = validator.blacklist(trimmed, "[^a-zA-ZÀ-ÿ '-]");
    if (cleaned !== trimmed)
        return "Name can only include letters, spaces, hyphens, or apostrophes.";
    return null;
};

const isValidEmail = email => {
    if (!email || typeof email !== 'string')
        return "Please provide your email address.";
    if (!validator.isEmail(email))
        return "Please enter a valid email address.";
    return null;
};

const isValidPassword = password => {
    if (!password || typeof password !== 'string')
        return "Please enter a password.";
    const options = {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    };
    if (!validator.isStrongPassword(password, options))
        return "Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.";
    return null;
};

const isPasswordMatch = (password, confirmPassword) => {
    if (!confirmPassword || typeof confirmPassword !== 'string')
        return "Please confirm your password.";
    if (password !== confirmPassword)
        return "Passwords do not match. Please try again.";
    return null;
};

app.post("/register", async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password || !confirmPassword)
            return res.status(400).json({ error: "All fields are required. Please fill in all the details." });

        const validationError =
            isValidName(name) ||
            isValidEmail(email) ||
            isValidPassword(password) ||
            isPasswordMatch(password, confirmPassword);

        if (validationError)
            return res.status(400).json({ error: validationError });

        const normalizedEmail = validator.normalizeEmail(email);
        const normalizedName = validator.trim(name).toLowerCase();

        const users = read_db();

        if (users.find(user => user.email === normalizedEmail))
            return res.status(400).json({ error: "This email is already registered. Try logging in or use another email." });

        if (users.find(user => user.name.toLowerCase() === normalizedName))
            return res.status(400).json({ error: "This username is already taken. Please choose a different name." });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            id: crypto.randomUUID(),
            name: validator.trim(name),
            email: normalizedEmail,
            password: hashedPassword,
            isVerified: false,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        write_db(users);

        res.status(201).json({
            message: "Registration successful! You can now log in.",
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: "Something went wrong on our side. Please try again later." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password)
            return res.status(400).json({ error: "Please provide both your username/email and password." });

        const users = read_db();

        let user;
        if (validator.isEmail(identifier)) {
            const normalizedEmail = validator.normalizeEmail(identifier);
            user = users.find(u => u.email === normalizedEmail);
        } else {
            const normalizedName = validator.trim(identifier).toLowerCase();
            user = users.find(u => u.name.toLowerCase() === normalizedName);
        }

        if (!user)
            return res.status(400).json({ error: "No account found with the provided username/email." });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(400).json({ error: "Incorrect password. Please try again." });

        res.status(200).json({
            message: "Login successful! Welcome back.",
            user: { id: user.id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Something went wrong on our side. Please try again later." });
    }
});

app.listen(PORT, HOST, () => {
    console.log(`✅ Server is running at http://${HOST}:${PORT}`);
});
