const express = require("express");
const dotenv = require("dotenv");
const { prisma } = require("./db/config");
const jsonwebtoken = require("jsonwebtoken");
const bcrypt = require("bcrypt");

dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
    "68d97a7b7965450091cd86a139a66caaca857c05511860b11b0064e388ba105328de791c8336dd7561f52ea7f2fa64f2d09810cfea12978b571cdceab05270b";
const SALT_ROUNDS = 10;

// Signup Endpoint
app.post("/api/auth/signup", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const existingUser = await prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            return res.status(400).json({ error: "Email already in use" });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const user = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
            },
        });

        res.status(201).json({
            message: "User created successfully",
            userId: user.id,
        });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Login Endpoint
app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res
            .status(400)
            .json({ error: "Email and password are required" });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const accessToken = jsonwebtoken.sign({ user }, JWT_SECRET, {
            expiresIn: "1d",
        });

        res.status(200).json({
            userdata: {
                id: user.id,
                name: user.name,
                email: user.email,
            },
            accesstoken: accessToken,
        });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.listen(PORT, () => {
    console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports = app;
