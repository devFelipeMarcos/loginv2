const express = require("express");
const sqlite3 = require("better-sqlite3"); // Alterado para better-sqlite3
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
const saltRounds = 10;
const JWT_SECRET = "seu-segredo-aqui"; // Em produção, utilize variável de ambiente para o segredo

// Inicializando o banco de dados SQLite
const db = new sqlite3("./users.db", { verbose: console.log }); // Alterado para better-sqlite3

// Configuração de middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  cors({
    origin: "http://localhost:5500", // Altere para a URL do seu front-end conforme necessário
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Criação da tabela de usuários, se não existir
db.prepare(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`
).run();

// Middleware de autenticação via JWT
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Token inválido" });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: "Token não fornecido" });
  }
};

// Rota de registro
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Dados incompletos" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "A senha deve ter no mínimo 6 caracteres" });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const stmt = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    );
    const info = stmt.run(username, hashedPassword);

    res.status(201).json({
      success: true,
      message: "Usuário cadastrado com sucesso!",
      userId: info.lastInsertRowid,
    });
  } catch (error) {
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota de login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Dados incompletos" });
    }

    const stmt = db.prepare("SELECT * FROM users WHERE username = ?");
    const user = stmt.get(username);

    if (!user) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const match = await bcrypt.compare(password, user.password_hash);

    if (match) {
      // Geração de token JWT com validade de 1 hora
      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "1h" }
      );
      res.json({
        success: true,
        message: "Login bem-sucedido!",
        userId: user.id,
        token: token,
      });
    } else {
      res.status(401).json({ error: "Credenciais inválidas" });
    }
  } catch (error) {
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota protegida de exemplo
app.get("/dashboard", authenticateUser, (req, res) => {
  res.json({ message: "Área restrita", user: req.user });
});

// Middleware para gerenciamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
