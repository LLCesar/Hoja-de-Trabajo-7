import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { users } from "./users.js";

dotenv.config();
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 4000;
const SECRET_KEY = process.env.JWT_SECRET;

//Endpoint de login que genera el token
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  //Buscar usuario
  const user = users.find(u => u.email === email && u.password === password);

  if (!user) {
    return res.status(401).json({ message: "Credenciales inválidas" });
  }

  //Generar token con duración de 30 segundos
  const token = jwt.sign(
    { id: user.id, email: user.email },
    SECRET_KEY,
    { expiresIn: "30s" }
  );

  res.json({ message: "Login exitoso", token });
});

//Middleware para proteger rutas
function verificarToken(req, res, next) {
  const header = req.headers["authorization"];

  if (!header) {
    return res.status(403).json({ message: "Token requerido" });
  }

  const token = header.split(" ")[1]; // Formato: Bearer <token>

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token inválido o expirado" });
    }

    req.user = decoded;
    next();
  });
}

//Rutas protegidas
app.get("/users", verificarToken, (req, res) => {
  res.json(users);
});

app.put("/users/:id", verificarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const { name, email } = req.body;

  const user = users.find(u => u.id === id);
  if (!user) {
    return res.status(404).json({ message: "Usuario no encontrado" });
  }

  if (name) user.name = name;
  if (email) user.email = email;

  res.json({ message: "Usuario actualizado", user });
});

app.delete("/users/:id", verificarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const index = users.findIndex(u => u.id === id);

  if (index === -1) {
    return res.status(404).json({ message: "Usuario no encontrado" });
  }

  users.splice(index, 1);
  res.json({ message: "Usuario eliminado" });
});

//Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
