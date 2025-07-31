const express = require('express');
const dotenv = require('dotenv');
const validator = require('validator');
const bcrypt = require('bcrypt');
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

if (!fs.existsSync(DB_F)) write_db([]);

const isValidName = name => {
    if (!name || typeof name !== 'string')
        return "Name is required";
    const trimmed = validator.trim(name);
    if (!validator.isLength(trimmed, { min: 3, max: 50 }))
        return "Name must be between 3 and 50 characters";
    const cleaned = validator.blacklist(trimmed, "[^a-zA-ZÀ-ÿ '-]");
    if (cleaned !== trimmed)
        return "Name can only contain letters, spaces, hyphens, or apostrophes";
    return null;
};

const isValidEmail = email => {
    if (!email || typeof email !== 'string')
        return "Email is required";
    if (!validator.isEmail(email))
        return "Invalid email format";
    return null;
};

const isValidPassword = password => {
    if (!password || typeof password !== 'string')
        return "Password is required";
    const options = {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    };
    if (!validator.isStrongPassword(password, options))
        return "Password must be at least 8 characters and include uppercase, lowercase, number, and symbol";
    return null;
};

const isPasswordMatch = (password, confirmPassword) => {
    if (!confirmPassword || typeof confirmPassword !== 'string')
        return "Confirm password is required";
    if (password !== confirmPassword)
        return "Passwords do not match";
    return null;
};

app.post("/register", async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password || !confirmPassword)
            return res.status(400).json({ error: "All fields (name, email, password, confirmPassword) are required" });

        const validationError =
            isValidName(name) ||
            isValidEmail(email) ||
            isValidPassword(password) ||
            isPasswordMatch(password, confirmPassword);

        if (validationError) return res.status(400).json({ error: validationError });

        const normalizedEmail = validator.normalizeEmail(email);
        const normalizedName = validator.trim(name).toLowerCase();

        const users = read_db();

        if (users.find(user => user.email === normalizedEmail))
            return res.status(400).json({ error: "Email already exists" });

        if (users.find(user => user.name.toLowerCase() === normalizedName))
            return res.status(400).json({ error: "Name already exists" });

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
            message: "User registered successfully",
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.listen(PORT, HOST, () => {
    console.log(`✅ Server is running at http://${HOST}:${PORT}`);
});
