const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Base de dados SQLite em memória vulnerável
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin')");
    db.run("INSERT INTO users VALUES (2, 'joao', 'password123', 'user')");
});

// 1. VULNERABILIDADE: Injeção de Dependência / Versões desatualizadas & Hardcoded Secrets

const JWT_SECRET = "super_secret_jwt_key_12345"; // Segredo em hardcode

// 2. VULNERABILIDADE: SQL Injection (A03:2021)
app.get('/login', (req, res) => {
    const username = req.query.user;
    const password = req.query.pass;

    // Concatenação direta de strings na query SQL permitindo SQLi
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.all(query, (err, rows) => {
        if (err) {
            res.status(500).send("Erro na base de dados");
        } else if (rows.length > 0) {
            res.send(`Bem-vindo de volta, ${rows[0].username}! Papel: ${rows[0].role}`);
        } else {
            res.status(401).send("Credenciais inválidas");
        }
    });
});

// 3. VULNERABILIDADE: Cross-Site Scripting (XSS) Refletido (A03:2021)
app.get('/search', (req, res) => {
    const query = req.query.q;
    // O input do utilizador é injetado diretamente no HTML sem qualquer sanitização
    res.send(`<h1>Resultados da pesquisa para:</h1> <p>${query}</p>`);
});

// 4. VULNERABILIDADE: Remote Code Execution / Command Injection (A03:2021)
app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    
    // Execução direta de comandos no sistema operativo com input não validado
    exec(`ping -c 1 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            res.send(`Erro ao executar o comando: ${stderr}`);
            return;
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

// 5. VULNERABILIDADE: Falha de Controlo de Acessos / Broken Object Level Authorization (A01:2021)
app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    // Não valida se o utilizador autenticado tem permissões para ver este ID específico
    db.get(`SELECT id, username, role FROM users WHERE id = ${userId}`, (err, row) => {
        if (err || !row) {
            res.status(404).send("Utilizador não encontrado");
        } else {
            res.json(row);
        }
    });
});

app.listen(3000, () => {
    console.log('Servidor vulnerável a correr na porta 3000');
});

// 6. VULNERABILIDADE DE TESTE: Code Injection via eval
app.get('/calc', (req, res) => {
    const expr = req.query.expr;
    // O SonarCloud deteta imediatamente o uso de eval como uma Vulnerabilidade Crítica de Segurança
    const result = eval(expr); 
    res.send(`Resultado: ${result}`);
});
