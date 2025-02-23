const bcrypt = require("bcryptjs");

const express = require("express");
const mysql = require("mysql");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "puzzle_peel",
});

app.post("/addUser", async (req, res) => {
  console.log(req.body);
  const { email, userName, password } = req.body;

  if (!email || !userName || !password) {
    return res
      .status(400)
      .json({ error: "Email, Username, and Password are required" });
  }

  const checkEmailSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkEmailSql, [email], async (err, result) => {
    if (err) return res.status(500).json(err);
    if (result.length > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
      if (err)
        return res.status(500).json({ error: "Error encrypting password" });

      const sql =
        "INSERT INTO users (email, username, password) VALUES (?, ?, ?)";
      db.query(sql, [email, userName, hashedPassword], (err, result) => {
        if (err) return res.status(500).json(err);
        return res
          .status(201)
          .json({ message: "User registered successfully" });
      });
    });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, result) => {
    if (err) return res.status(500).json(err);

    if (result.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const storedPassword = result[0].password;
    bcrypt.compare(password, storedPassword, (err, isMatch) => {
      if (err)
        return res.status(500).json({ error: "Error comparing passwords" });

      if (isMatch) {
        return res.status(200).json({ message: "Login successful" });
      } else {
        return res.status(400).json({ error: "Invalid credentials" });
      }
    });
  });
});

app.listen(8081, () => console.log("Server Running...."));
