const express = require('express');
const dotenv = require('dotenv');
const validator = require('validator');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT;
const HOST = process.env.HOST;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRATION = process.env.JWT_EXPIRATION;
const DB_F = path.join(__dirname, 'db.json');

if (!PORT || !HOST || !JWT_SECRET || !JWT_EXPIRATION) {
    console.error("❌ Missing required environment variables. Please set PORT, HOST, JWT_SECRET, and JWT_EXPIRATION in your .env file.");
    process.exit(1);
}

const read_db = () => JSON.parse(fs.readFileSync(DB_F, 'utf8'));
const write_db = data => fs.writeFileSync(DB_F, JSON.stringify(data, null, 2));
const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendVerificationEmail = async (email, code) => {
    try {
        const testAccount = await nodemailer.createTestAccount();
        const transporter = nodemailer.createTransport({
            host: testAccount.smtp.host,
            port: testAccount.smtp.port,
            secure: testAccount.smtp.secure,
            auth: {
                user: testAccount.user,
                pass: testAccount.pass,
            },
        });
        try {
            const info = await transporter.sendMail({
                from: 'MyApp <no-reply@myapp.com>',
                to: email,
                subject: 'Verify your email',
                text: `Your verification code is: ${code}`,
            });
            console.log("Preview URL:", nodemailer.getTestMessageUrl(info));
        } catch (emailError) {
            console.error("Email sending error:", emailError);
            return { error: "Failed to send verification email. Please try again later." };
        }
    } catch (error) {
        console.error("Error setting up email transporter:", error);
        return { error: "Failed to set up email transporter. Please try again later." };
    }
};


if (!fs.existsSync(DB_F))
    write_db([]);

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader)
        return res.status(401).json({ error: "Authorization header is missing." });

    const token = authHeader.split(' ')[1];
    if (!token)
        return res.status(401).json({ error: "Token is missing." });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error("Token verification error:", error);
        return res.status(403).json({ error: "Invalid or expired token." });
    }
};

const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Access denied. Admins only." });
    }
    next();
};

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
        if (!hashedPassword)
            return res.status(500).json({ error: "Failed to hash password. Please try again later." });

        const verificationCode = generateVerificationCode();

        const newUser = {
            id: crypto.randomUUID(),
            name: validator.trim(name),
            email: normalizedEmail,
            password: hashedPassword,
            role: "user",
            verificationCode,
            verificationCodeExpires: Date.now() + 20 * 60 * 1000,
            isVerified: false,
            createdAt: new Date().toISOString()
        };

        const emailError = await sendVerificationEmail(normalizedEmail, verificationCode);
        if (emailError) {
            console.error("Email sending error:", emailError);
            return res.status(500).json({ error: emailError.error });
        }

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

app.post('/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!code || typeof code !== 'string')
            return res.status(400).json({ error: "Verification code is required." });
        if (isValidEmail(email))
            return res.status(400).json({ error: "Please provide a valid email address." });
        const normalizedEmail = validator.normalizeEmail(email);
        const users = read_db();
        const user = users.find(u => u.email === normalizedEmail);
        if (!user)
            return res.status(404).json({ error: "User not found. Please check your email." });
        if (user.isVerified)
            return res.status(400).json({ error: "This email is already verified." });
        if (user.verificationCode !== code)
            return res.status(400).json({ error: "Invalid verification code. Please try again." });
        if (user.verificationCodeExpires < Date.now())
            return res.status(400).json({ error: "Verification code has expired. Please request a new code." });
        user.isVerified = true;
        user.verificationCode = null;
        user.verificationCodeExpires = null;
        write_db(users);
        res.status(200).json({
            message: "Email verification successful! You can now log in."
        });
    } catch (error) {
        console.error("Email verification error:", error);
        res.status(500).json({ error: "Something went wrong while verifying your email. Please try again later." });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password)
            return res.status(400).json({ error: "Email or username and password are required." });

        const users = read_db();
        let user;
        if (validator.isEmail(identifier))
            user = users.find(u => u.email === validator.normalizeEmail(identifier));
        else
            user = users.find(u => u.name.toLowerCase() === validator.trim(identifier).toLowerCase());

        if (!user)
            return res.status(404).json({ error: "User not found. Please check your email or username." });

        if (!user.isVerified)
            return res.status(403).json({ error: "Please verify your email before logging in." });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid)
            return res.status(401).json({ error: "Invalid password. Please try again." });

        const token = jwt.sign(
            { userId: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRATION }
        );

        if (!token)
            return res.status(500).json({ error: "Failed to generate authentication token. Please try again later." });
        console.log(token);
        res.status(200).json({
            message: "Login successful!",
            token: token
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Something went wrong on our side. Please try again later." });
    }
});

app.get('/', authenticateToken, (req, res) => {
    res.status(200).json({
        message: `Welcome! You are logged in as ${req.user.email}`,
    });
});

app.get('/admin', authenticateToken, authorizeAdmin, (req, res) => {
    res.status(200).json({
        message: `Hello Admin ${req.user.email}, you have access to this admin route.`,
    });
});

app.listen(PORT, HOST, () => {
    console.log(`✅ Server is running at http://${HOST}:${PORT}`);
});


// register
// {
//     "name": "John Doe",
//     "email": "johndoe@example.com",
//     "password": "StrongP@ssw0rd",
//     "confirmPassword": "StrongP@ssw0rd"
// }

// /login
// {
//     "identifier": "johndoe@example.com",
//     "password": "StrongP@ssw0rd"
// }

// Authorization : Bearer token