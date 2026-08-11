require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.static("public"));
app.use(express.json());
app.use(cors());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    createIndexes();
  })
  .catch((err) => console.log(err));

// ─── INDEXES ──────────────────────────────────────────────────────────────────
async function createIndexes() {
  // INDEX 1 — unique index on username
  await mongoose.connection
    .collection("users")
    .createIndex({ username: 1 }, { unique: true });

  // INDEX 2 — compound index on embedded projects array: search by (userId, project name)

  await mongoose.connection
    .collection("users")
    .createIndex(
      { _id: 1, "projects.name": 1 },
      { name: "idx_users_embedded_project_name" },
    );

  // INDEX 3 — multikey index on embedded projects.tags array

  await mongoose.connection
    .collection("users")
    .createIndex(
      { "projects.tags": 1 },
      { name: "idx_users_embedded_project_tags_multikey" },
    );
}

// ─── SCHEMAS ──────────────────────────────────────────────────────────────────

const ElementSchema = new mongoose.Schema(
  {
    id: String,
    type: String,
    x: Number,
    y: Number,
    props: mongoose.Schema.Types.Mixed,
  },
  { _id: false },
);

const ProjectSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => new mongoose.Types.ObjectId().toString(),
  },
  name: String,
  canvasBg: { type: String, default: "#ffffff" },
  elements: [ElementSchema],
  tags: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const UserSchema = new mongoose.Schema({
  fullName: String,
  username: { type: String, unique: true },
  password: String,
  projects: [ProjectSchema],
});

const User = mongoose.model("User", UserSchema);

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });
  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

app.post("/signup", async (req, res) => {
  const { fullName, username, password } = req.body;
  try {
    // QUERY: db.users.findOne({ username: <username> })
    const existing = await User.findOne({ username });
    if (existing) return res.json({ message: "Username already exists" });

    const hashed = await bcrypt.hash(password, 10);
    // QUERY: db.users.insertOne({ fullName, username, password, projects: [] })
    const user = new User({
      fullName,
      username,
      password: hashed,
      projects: [],
    });
    await user.save();
    res.json({ message: "Signup successful" });
  } catch (err) {
    res.status(500).json({ message: "Error", err });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    // QUERY: db.users.findOne({ username: <username> })
    const user = await User.findOne({ username });
    if (!user) return res.json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ message: "Wrong password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ message: "Login successful", token, fullName: user.fullName });
  } catch (err) {
    res.status(500).json({ message: "Error", err });
  }
});

// QUERY: db.users.findOne({ _id: <id> }, { projection: { fullName:1, username:1 } })
app.get("/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id, "fullName username");
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ fullName: user.fullName, username: user.username });
});

// QUERY update fullname
app.put("/profile/name", auth, async (req, res) => {
  const { fullName } = req.body;
  if (!fullName || !fullName.trim()) {
    return res.status(400).json({ message: "Full name cannot be empty" });
  }
  try {
    await User.findByIdAndUpdate(req.user.id, {
      $set: { fullName: fullName.trim() },
    });
    res.json({ message: "Name updated", fullName: fullName.trim() });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to update name", err: err.message });
  }
});

app.put("/profile/username", auth, async (req, res) => {
  const { username } = req.body;
  if (!username || !username.trim()) {
    return res.status(400).json({ message: "Username cannot be empty" });
  }
  const cleaned = username.trim().toLowerCase();
  try {
    // QUERY: check uniqueness before applying $set
    const existing = await User.findOne({ username: cleaned });
    if (existing && existing._id.toString() !== req.user.id) {
      return res.json({ message: "Username taken" });
    }
    await User.findByIdAndUpdate(req.user.id, {
      $set: { username: cleaned },
    });
    res.json({ message: "Username updated", username: cleaned });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to update username", err: err.message });
  }
});
// QUERY update password
app.put("/profile/password", auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "Both passwords are required" });
  }
  if (newPassword.length < 6) {
    return res
      .status(400)
      .json({ message: "New password must be at least 6 characters" });
  }
  try {
    // Fetch the full user doc
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.json({ message: "Wrong password" });
    const newHash = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.user.id, {
      $set: { password: newHash },
    });
    res.json({ message: "Password updated" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to update password", err: err.message });
  }
});

app.delete("/profile", auth, async (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res
      .status(400)
      .json({ message: "Password required to delete account" });
  }
  try {
    // Fetch user to verify password before deletion
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ message: "Wrong password" });

    await User.deleteOne({ _id: req.user.id });
    res.json({ message: "Account deleted" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to delete account", err: err.message });
  }
});

// ─── PROJECT ROUTES ───────────────────────────────────────────────────────────
app.get("/projects", auth, async (req, res) => {
  const user = await User.findById(req.user.id, "projects");
  if (!user) return res.status(404).json({ message: "Not found" });
  res.json(user.projects);
});
// QUERY push project into projects array
app.post("/projects", auth, async (req, res) => {
  const { name, canvasBg, elements, tags } = req.body;
  const project = {
    _id: new mongoose.Types.ObjectId().toString(),
    name: name || "Untitled Project",
    canvasBg: canvasBg || "#ffffff",
    elements: elements || [],
    tags: tags || [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  await User.findByIdAndUpdate(req.user.id, {
    $push: { projects: project },
  });

  res.json(project);
});
// QUERY search projects
app.get("/projects/search", auth, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json([]);
  const results = await User.aggregate([
    { $match: { _id: new mongoose.Types.ObjectId(req.user.id) } },
    { $unwind: "$projects" },
    { $match: { "projects.name": { $eq: q } } },
    { $replaceRoot: { newRoot: "$projects" } },
  ]);
  res.json(results);
});
// QUERY updating project in projects array
app.put("/projects/:projectId", auth, async (req, res) => {
  const { name, canvasBg, elements } = req.body;
  const pid = req.params.projectId;

  await User.findOneAndUpdate(
    { _id: req.user.id, "projects._id": pid },
    {
      $set: {
        "projects.$.name": name,
        "projects.$.canvasBg": canvasBg,
        "projects.$.elements": elements,
        "projects.$.updatedAt": new Date(),
      },
    },
  );

  res.json({ message: "Project updated" });
});

// QUERY delete project from array
app.delete("/projects/:projectId", auth, async (req, res) => {
  const pid = req.params.projectId;

  await User.findByIdAndUpdate(req.user.id, {
    $pull: { projects: { _id: pid } },
  });

  res.json({ message: "Project deleted" });
});

// ─── TAG ROUTES ────────────────────────────

// QUERY add tags to tags array in project in projects array
app.post("/projects/:projectId/tags", auth, async (req, res) => {
  const { tag } = req.body;
  const pid = req.params.projectId;

  await User.findOneAndUpdate(
    { _id: req.user.id, "projects._id": pid },
    {
      $addToSet: { "projects.$.tags": tag },
      $set: { "projects.$.updatedAt": new Date() },
    },
  );

  res.json({ message: "Tag added" });
});
//QUERY delete tag
app.delete("/projects/:projectId/tags/:tag", auth, async (req, res) => {
  const { projectId, tag } = req.params;

  await User.findOneAndUpdate(
    { _id: req.user.id, "projects._id": projectId },
    {
      $pull: { "projects.$.tags": tag },
      $set: { "projects.$.updatedAt": new Date() },
    },
  );

  res.json({ message: "Tag removed" });
});

app.delete("/projects/:projectId/tags/last", auth, async (req, res) => {
  const pid = req.params.projectId;

  await User.findOneAndUpdate(
    { _id: req.user.id, "projects._id": pid },
    {
      $pop: { "projects.$.tags": 1 },
      $set: { "projects.$.updatedAt": new Date() },
    },
  );

  res.json({ message: "Last tag removed ($pop)" });
});
app.put("/projects/:projectId/tags", auth, async (req, res) => {
  const { tags } = req.body;
  const pid = req.params.projectId;

  await User.findOneAndUpdate(
    { _id: req.user.id, "projects._id": pid },
    {
      $set: {
        "projects.$.tags": tags,
        "projects.$.updatedAt": new Date(),
      },
    },
  );

  res.json({ message: "Tags updated" });
});

// ─── PALETTE ROUTES ───────────────────────────────────────────────

const PaletteSchema = new mongoose.Schema({
  colors: [String],
  tags: [String],
  likes: { type: Number, default: 0 },
});
const Palette = mongoose.model("Palette", PaletteSchema);

app.get("/seed", async (req, res) => {
  await Palette.deleteMany({});
  await Palette.insertMany([
    {
      colors: ["#1a1a1a", "#333", "#666"],
      tags: ["dark", "minimal", "neutral"],
      likes: 12,
    },
    {
      colors: ["#111", "#222", "#444", "#777"],
      tags: ["dark", "neutral"],
      likes: 18,
    },
    {
      colors: ["#2c2c2c", "#3a3a3a", "#555"],
      tags: ["dark", "minimal"],
      likes: 9,
    },
    {
      colors: ["#ff5733", "#ff8d1a", "#ffc300"],
      tags: ["bright", "warm", "orange"],
      likes: 30,
    },
    {
      colors: ["#ff6b6b", "#ffa36c", "#ffd166"],
      tags: ["bright", "warm", "red"],
      likes: 25,
    },
    {
      colors: ["#ff4e50", "#fc913a", "#f9d423"],
      tags: ["bright", "warm", "orange"],
      likes: 22,
    },
    {
      colors: ["#00c9ff", "#92fe9d", "#00bfa5"],
      tags: ["bright", "cool", "blue"],
      likes: 27,
    },
    {
      colors: ["#2193b0", "#6dd5ed", "#b2fefa"],
      tags: ["cool", "blue"],
      likes: 19,
    },
    {
      colors: ["#0f2027", "#203a43", "#2c5364"],
      tags: ["dark", "cool", "blue"],
      likes: 35,
    },
    {
      colors: ["#a8edea", "#fed6e3", "#fbc2eb"],
      tags: ["pastel", "light", "pink"],
      likes: 28,
    },
    {
      colors: ["#ffdde1", "#ee9ca7", "#fad0c4"],
      tags: ["pastel", "pink", "warm"],
      likes: 20,
    },
    {
      colors: ["#d4fc79", "#96e6a1", "#b2fefa"],
      tags: ["pastel", "green", "cool"],
      likes: 23,
    },
    {
      colors: ["#c9d6ff", "#e2e2e2", "#f5f7fa"],
      tags: ["minimal", "light", "neutral"],
      likes: 14,
    },
    {
      colors: ["#ffffff", "#eaeaea", "#dcdcdc"],
      tags: ["minimal", "light", "neutral"],
      likes: 11,
    },
    {
      colors: ["#ff9a9e", "#fad0c4", "#fad0c4"],
      tags: ["pink", "pastel"],
      likes: 16,
    },
    {
      colors: ["#a18cd1", "#fbc2eb", "#f093fb"],
      tags: ["purple", "pastel"],
      likes: 21,
    },
    {
      colors: ["#667eea", "#764ba2", "#6b73ff"],
      tags: ["purple", "cool"],
      likes: 26,
    },
    {
      colors: ["#6a11cb", "#2575fc", "#4facfe"],
      tags: ["blue", "cool"],
      likes: 29,
    },
    {
      colors: ["#f7971e", "#ffd200", "#ff9a00"],
      tags: ["yellow", "warm"],
      likes: 17,
    },
    {
      colors: ["#ffe259", "#ffa751", "#ffcc70"],
      tags: ["yellow", "warm"],
      likes: 13,
    },
    {
      colors: ["#56ab2f", "#a8e063", "#7ed957"],
      tags: ["green", "nature"],
      likes: 24,
    },
    {
      colors: ["#11998e", "#38ef7d", "#57cc99"],
      tags: ["green", "cool"],
      likes: 19,
    },
    {
      colors: ["#654ea3", "#eaafc8", "#c471f5"],
      tags: ["purple", "pink"],
      likes: 18,
    },
    {
      colors: ["#ff7e5f", "#feb47b", "#ff9966"],
      tags: ["orange", "warm"],
      likes: 22,
    },
    {
      colors: ["#43cea2", "#185a9d", "#4facfe"],
      tags: ["blue", "green", "cool"],
      likes: 27,
    },
    {
      colors: ["#ffecd2", "#fcb69f", "#ff9a8b"],
      tags: ["warm", "light"],
      likes: 15,
    },
    {
      colors: ["#2b5876", "#4e4376", "#6a82fb"],
      tags: ["blue", "dark"],
      likes: 31,
    },
    {
      colors: ["#ff5f6d", "#ffc371", "#ff9a9e"],
      tags: ["red", "warm"],
      likes: 20,
    },
    {
      colors: ["#00f2fe", "#4facfe", "#43e97b"],
      tags: ["bright", "cool"],
      likes: 26,
    },
    {
      colors: ["#fa709a", "#fee140", "#ff9a9e"],
      tags: ["bright", "pink"],
      likes: 23,
    },
  ]);
  res.send("Seeded");
});

app.get("/palettes", async (req, res) => {
  const tag = req.query.tag;
  const query = tag ? { tags: tag } : {};
  const palettes = await Palette.find(query);
  res.json(palettes);
});
// QUERY inc likes
app.post("/like/:id", async (req, res) => {
  await Palette.findByIdAndUpdate(req.params.id, { $inc: { likes: 1 } });
  res.json({ message: "Liked" });
});
//QUERY top 5 palettes
app.get("/top-palettes", async (req, res) => {
  const result = await Palette.aggregate([
    { $sort: { likes: -1 } },
    { $limit: 5 },
  ]);
  res.json(result);
});

app.get("/reset", async (req, res) => {
  await Palette.deleteMany({});
  res.send("DB cleared");
});

app.listen(5000, () => {
  console.log("Server running on port 5000  http://localhost:5000/");
});
