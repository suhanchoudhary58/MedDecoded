const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL || "*" }));
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

// ── Auth routes ──────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });
  try {
    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rows.length) return res.status(400).json({ error: "Email already registered" });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO users (name,email,password_hash) VALUES ($1,$2,$3) RETURNING id,name,email", [name, email, hash]
    );
    const token = jwt.sign({ id: rows[0].id, email }, process.env.JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!rows.length) return res.status(400).json({ error: "Invalid email or password" });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(400).json({ error: "Invalid email or password" });
    const token = jwt.sign({ id: rows[0].id, email }, process.env.JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: rows[0].id, name: rows[0].name, email: rows[0].email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/auth/me", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT id,name,email,created_at FROM users WHERE id=$1", [req.user.id]);
  res.json(rows[0]);
});

// ── Health Profile ───────────────────────────────────────────────────────────
app.get("/api/profile", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM health_profiles WHERE user_id=$1", [req.user.id]);
  res.json(rows[0] || {});
});

app.post("/api/profile", auth, async (req, res) => {
  const { age, gender, blood_type, conditions, allergies, doctor, phone, notes } = req.body;
  await pool.query(`
    INSERT INTO health_profiles (user_id,age,gender,blood_type,conditions,allergies,doctor,phone,notes)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    ON CONFLICT (user_id) DO UPDATE SET
      age=$2,gender=$3,blood_type=$4,conditions=$5,allergies=$6,doctor=$7,phone=$8,notes=$9,updated_at=NOW()
  `, [req.user.id, age, gender, blood_type, conditions, allergies, doctor, phone, notes]);
  res.json({ success: true });
});

// ── Medicines ────────────────────────────────────────────────────────────────
app.get("/api/medicines", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM medicines WHERE user_id=$1 ORDER BY created_at", [req.user.id]);
  res.json(rows);
});

app.post("/api/medicines", auth, async (req, res) => {
  const { name, dosage, unit, frequency, times, notes, color } = req.body;
  const { rows } = await pool.query(
    "INSERT INTO medicines (user_id,name,dosage,unit,frequency,times,notes,color) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
    [req.user.id, name, dosage, unit, frequency, JSON.stringify(times), notes, color]
  );
  res.json(rows[0]);
});

app.put("/api/medicines/:id", auth, async (req, res) => {
  const { name, dosage, unit, frequency, times, notes, color } = req.body;
  await pool.query(
    "UPDATE medicines SET name=$1,dosage=$2,unit=$3,frequency=$4,times=$5,notes=$6,color=$7 WHERE id=$8 AND user_id=$9",
    [name, dosage, unit, frequency, JSON.stringify(times), notes, color, req.params.id, req.user.id]
  );
  res.json({ success: true });
});

app.delete("/api/medicines/:id", auth, async (req, res) => {
  await pool.query("DELETE FROM medicines WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ── Adherence ────────────────────────────────────────────────────────────────
app.get("/api/adherence", auth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM adherence_logs WHERE user_id=$1 AND date >= NOW() - INTERVAL '30 days'", [req.user.id]
  );
  const shaped = {};
  rows.forEach(r => {
    if (!shaped[r.date]) shaped[r.date] = {};
    if (!shaped[r.date][r.medicine_id]) shaped[r.date][r.medicine_id] = {};
    shaped[r.date][r.medicine_id][r.time_slot] = r.taken;
  });
  res.json(shaped);
});

app.post("/api/adherence", auth, async (req, res) => {
  const { medicine_id, date, time_slot, taken } = req.body;
  await pool.query(`
    INSERT INTO adherence_logs (user_id,medicine_id,date,time_slot,taken)
    VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT (user_id,medicine_id,date,time_slot) DO UPDATE SET taken=$5
  `, [req.user.id, medicine_id, date, time_slot, taken]);
  res.json({ success: true });
});

// ── Search History ───────────────────────────────────────────────────────────
app.get("/api/history", auth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id,search_type,query,searched_at FROM search_history WHERE user_id=$1 ORDER BY searched_at DESC LIMIT 50",
    [req.user.id]
  );
  res.json(rows);
});

app.post("/api/history", auth, async (req, res) => {
  const { search_type, query, result_json } = req.body;
  await pool.query(
    "INSERT INTO search_history (user_id,search_type,query,result_json) VALUES ($1,$2,$3,$4)",
    [req.user.id, search_type, query, JSON.stringify(result_json)]
  );
  res.json({ success: true });
});

app.get("/api/history/:id", auth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM search_history WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: "Not found" });
  res.json({ ...rows[0], result_json: rows[0].result_json });
});

app.delete("/api/history/:id", auth, async (req, res) => {
  await pool.query("DELETE FROM search_history WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  res.json({ success: true });
});

app.listen(process.env.PORT || 4000, () => console.log("MedDecoded API running on port 4000"));