const express = require("express");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();
const saltRounds = 10;
const JWT_SECRET = "seu-segredo-aqui"; // Em produção, utilize variável de ambiente para o segredo

// Caminho para o arquivo JSON de usuários
const usersFilePath = path.join(__dirname, "users.json");

// Função para ler os dados de usuários do arquivo JSON
const readUsersFromFile = () => {
  if (!fs.existsSync(usersFilePath)) {
    return [];
  }
  const data = fs.readFileSync(usersFilePath);
  return JSON.parse(data);
};

// Função para escrever os dados de usuários no arquivo JSON
const writeUsersToFile = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

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

    // Carrega os usuários do arquivo JSON
    const users = readUsersFromFile();

    // Verifica se o username já existe
    if (users.some((user) => user.username === username)) {
      return res.status(400).json({ error: "Usuário já existe" });
    }

    const newUser = {
      id: users.length + 1,
      username,
      password_hash: hashedPassword,
      created_at: new Date().toISOString(),
    };

    // Adiciona o novo usuário à lista
    users.push(newUser);

    // Salva os usuários de volta no arquivo JSON
    writeUsersToFile(users);

    res.status(201).json({
      success: true,
      message: "Usuário cadastrado com sucesso!",
      userId: newUser.id,
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

    // Carrega os usuários do arquivo JSON
    const users = readUsersFromFile();

    // Encontra o usuário pelo username
    const user = users.find((user) => user.username === username);

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
