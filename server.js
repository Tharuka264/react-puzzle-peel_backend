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

app.get("/getScores", (req, res) => {
  const query =
    "SELECT email, userName, highest_score FROM users ORDER BY highest_score DESC";
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).json({ message: "Error fetching users", error: err });
    } else {
      res.status(200).json(results);
    }
  });
});

app.put("/updateScore", (req, res) => {
  const { email, newScore } = req.body;

  if (!email || newScore === undefined) {
    return res.status(400).json({ message: "Email and newScore are required" });
  }

  const selectQuery = "SELECT highest_score FROM users WHERE email = ?";
  db.query(selectQuery, [email], (err, results) => {
    if (err) {
      return res
        .status(500)
        .json({ message: "Error fetching current score", error: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const currentScore = results[0].highest_score;

    if (newScore > currentScore) {
      const updateQuery = "UPDATE users SET highest_score = ? WHERE email = ?";
      db.query(updateQuery, [newScore, email], (err, updateResult) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Error updating score", error: err });
        }

        return res.status(200).json({ message: "Score updated successfully" });
      });
    } else {
      return res
        .status(200)
        .json({ message: "New score is not higher than current score" });
    }
  });
});

app.listen(8081, () => console.log("Server Running...."));
