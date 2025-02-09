const express = require("express"); //Para Inicalizar express
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid"); //Para generar IDs

const app = express();
const PORT = 3000; //Puerto usado
const SECRET_KEY = "mi_clave_secreta";
const USERS_FILE = "users.json";
const TASKS_FILE = "tareas.json";

app.use(express.json());

//Para leer usuarios registrados
const UsuariosRegistrados = () => {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE); 
  return JSON.parse(data);
};

//Para guardar usuarios
const guardarUsuarios = (usuarios) => {
  fs.writeFileSync(USERS_FILE, JSON.stringify(usuarios, null, 2));
};

//Para leer tareas
const leerTareas = () => {
  if (!fs.existsSync(TASKS_FILE)) return [];
  const data = fs.readFileSync(TASKS_FILE);
  return JSON.parse(data);
};

//Para guardar tareas
const guardarTareas = (tareas) => {
  fs.writeFileSync(TASKS_FILE, JSON.stringify(tareas, null, 2));
};

//verificacion del token JWT
const verificarToken = (req, res, next) => {
    const token = req.header("Authorization");
  
    if (!token || !token.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Token requerido" });
    }
  
    const tokenSinBearer = token.split(" ")[1];
  
    try {
      const verificado = jwt.verify(tokenSinBearer, SECRET_KEY);
      req.usuario = verificado;
      next();
    } catch (err) {
      console.log("Error al verificar token:", err.message);
      res.status(400).json({ error: "Token inválido" });
    }
  };

//Registro de usuario
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Faltan datos" });
  }

  let usuarios = UsuariosRegistrados();
  if (usuarios.some((user) => user.username === username)) {
    return res.status(400).json({ error: "El usuario ya existe" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  usuarios.push({ username, password: hashedPassword });
  guardarUsuarios(usuarios);

  res.status(201).json({ message: "Usuario registrado" });
});

//Inicio de sesión
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  let usuarios = UsuariosRegistrados();

  const usuario = usuarios.find((user) => user.username === username);
  if (!usuario) {
    return res.status(400).json({ error: "Usuario no encontrado" });
  }

  const esValida = bcrypt.compareSync(password, usuario.password);
  if (!esValida) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }

  const token = jwt.sign({ username: usuario.username }, SECRET_KEY, { expiresIn: "2h" });

  res.json({ message: "Inicio de sesión exitoso", token });
});

//Obtener todas las tareas
app.get("/tasks", verificarToken, (req, res) => {
  const tareas = leerTareas();
  res.json(tareas);
});

//Agregar nueva tarea
app.post("/tasks", verificarToken, (req, res) => {
  const { title, description } = req.body;
  if (!title) {
    return res.status(400).json({ error: "El título es obligatorio" });
  }

  let tareas = leerTareas();
  const nuevaTarea = {
    id: uuidv4(),
    title,
    description: description || "",
    completed: false,
    user: req.usuario.username,
  };

  tareas.push(nuevaTarea);
  guardarTareas(tareas);

  res.status(201).json({ message: "Nueva Tarea Creada", tarea: nuevaTarea });
});

//Esta actividad un dolor de cabeza

//Editar tarea por id
app.put("/tasks/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  const { title, description, completed } = req.body;

  let tareas = leerTareas();
  const tarea = tareas.find((t) => t.id === id && t.user === req.usuario.username);
  if (!tarea) {
    return res.status(404).json({ error: "Tarea no encontrada, no se pudo completar la accion" });
  }

  if (title) tarea.title = title;
  if (description !== undefined) tarea.description = description;
  if (completed !== undefined) tarea.completed = completed;

  guardarTareas(tareas);
  res.json({ message: "Tarea actualizada", tarea });
});

//Eliminar tarea por id
app.delete("/tasks/:id", verificarToken, (req, res) => {
  const { id } = req.params;

  let tareas = leerTareas();
  const tareasFiltradas = tareas.filter((t) => !(t.id === id && t.user === req.usuario.username));

  if (tareas.length === tareasFiltradas.length) {
    return res.status(404).json({ error: "Tarea no encontrada, no se borro la tarea" });
  }

  guardarTareas(tareasFiltradas);
  res.json({ message: "Tarea borrada correctamente" });
});

//Error 404
app.use((req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

//Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
