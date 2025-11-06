// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 3000;

// === CONFIG ===
const MONGO_URI = process.env.MONGO_URI; // set in Render Environment Variables
const JWT_SECRET = process.env.JWT_SECRET || "supersecret"; // set in Render env for security

// === MIDDLEWARE ===
app.use(cors()); // allow cross-origin requests
app.use(express.json()); // parse JSON

// === CONNECT TO MONGO ===
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// === USER MODEL ===
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    data: { type: Object, default: {} }
});
const User = mongoose.model("User", userSchema);

// === ROUTES ===

// Ping route to test backend
app.get("/ping", (req, res) => {
    res.json({ message: "pong" });
});

// Register a new user
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, error: "Missing username or password" });

    try {
        const exists = await User.findOne({ username });
        if (exists) return res.json({ success: false, error: "Username already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Login a user
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, error: "Missing username or password" });

    try {
        const user = await User.findOne({ username });
        if (!user) return res.json({ success: false, error: "User not found" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.json({ success: false, error: "Incorrect password" });

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

        res.json({ success: true, token, username: user.username, data: user.data });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Sync user data
app.post("/sync", async (req, res) => {
    const { token, data } = req.body;
    if (!token || !data) return res.json({ success: false, error: "Missing token or data" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) return res.json({ success: false, error: "User not found" });

        user.data = data;
        await user.save();
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Start server
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
