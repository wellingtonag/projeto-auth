// server.js
require('dotenv').config(); // Permite carregar as variáveis do arquivo .env

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Conecta ao banco de dados Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Configura o Express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); // Para arquivos estáticos (CSS)

// Rotas da aplicação 

// 1. Rota para exibir a página inicial (formulário de registro/login)
app.get('/', (req, res) => {
  res.render('index', { message: null });
});

// 2. Endpoint de Registro
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.render('index', { message: 'Usuário e senha são obrigatórios.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10); // 10 é o 'salt' (nível de segurança)

    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, passwordHash]);

    res.render('index', { message: 'Usuário registrado com sucesso!' });
  } catch (err) {
    if (err.code === '23505') { // Código de erro para violação de UNIQUE
      return res.render('index', { message: 'Este usuário já existe.' });
    }
    console.error(err);
    res.status(500).render('index', { message: 'Erro ao registrar. Tente novamente.' });
  }
});

// 3. Endpoint de Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.render('index', { message: 'Usuário não encontrado.' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (passwordMatch) {
      res.render('dashboard', { username: username });
    } else {
      res.render('index', { message: 'Senha incorreta.' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).render('index', { message: 'Erro no login. Tente novamente.' });
  }
});
// ...

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});