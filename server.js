require("dotenv").config();
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "secret";

const usersFile = path.join(__dirname, "data", "users.json");
const projectsFile = path.join(__dirname, "data", "projects.json");
const tasksFile = path.join(__dirname, "data", "tasks.json");
const publicDir = path.join(__dirname, "public");

function readJSON(file) {
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, "utf8") || "[]");
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function sendJSON(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => (body += chunk.toString()));
    req.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch (err) {
        reject(err);
      }
    });
  });
}
function verifyToken(req) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return null;
  const token = authHeader.split(" ")[1];
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const method = req.method;
  const pathname = parsedUrl.pathname;

  // Serve static files
  if (method === "GET" && !pathname.startsWith("/api")) {
    const filePath = path.join(publicDir, pathname === "/" ? "index.html" : pathname);
    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.writeHead(404);
        res.end("Not found");
      } else {
        const ext = path.extname(filePath);
        const mime = {
          ".html": "text/html",
          ".css": "text/css",
          ".js": "application/javascript",
        }[ext] || "text/plain";
        res.writeHead(200, { "Content-Type": mime });
        res.end(content);
      }
    });
    return;
  }

  if (pathname === "/api/auth/register" && method === "POST") {
    const { name, email, password } = await parseBody(req);
    if (!name || !email || !password) return sendJSON(res, 400, { error: "Missing fields" });
    let users = readJSON(usersFile);
    if (users.find(u => u.email === email)) return sendJSON(res, 400, { error: "Email already exists" });
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now(), name, email, passwordHash };
    users.push(newUser);
    writeJSON(usersFile, users);
    const token = jwt.sign({ id: newUser.id, name, email }, JWT_SECRET, { expiresIn: "7d" });
    return sendJSON(res, 201, { user: { id: newUser.id, name, email }, token });
  }

  if (pathname === "/api/auth/login" && method === "POST") {
    const { email, password } = await parseBody(req);
    const users = readJSON(usersFile);
    const user = users.find(u => u.email === email);
    if (!user) return sendJSON(res, 401, { error: "Invalid email or password" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return sendJSON(res, 401, { error: "Invalid email or password" });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    return sendJSON(res, 200, { user: { id: user.id, name: user.name, email: user.email }, token });
  }

  if (pathname === "/api/me" && method === "GET") {
    const decoded = verifyToken(req);
    if (!decoded) return sendJSON(res, 401, { error: "Unauthorized" });
    const users = readJSON(usersFile);
    const user = users.find(u => u.id === decoded.id);
    return user ? sendJSON(res, 200, { user }) : sendJSON(res, 404, { error: "Not found" });
  }

  if (pathname === "/api/projects" && method === "GET") {
    const decoded = verifyToken(req);
    if (!decoded) return sendJSON(res, 401, { error: "Unauthorized" });
    return sendJSON(res, 200, { projects: readJSON(projectsFile) });
  }

  if (pathname === "/api/projects" && method === "POST") {
    const decoded = verifyToken(req);
    if (!decoded) return sendJSON(res, 401, { error: "Unauthorized" });
    const { name, description, dueDate } = await parseBody(req);
    const projects = readJSON(projectsFile);
    const newProject = {
      id: Date.now(),
      name,
      description,
      dueDate,
      owner: decoded.id,
      createdAt: new Date().toISOString(),
    };
    projects.push(newProject);
    writeJSON(projectsFile, projects);
    return sendJSON(res, 201, { project: newProject });
  }

  if (pathname === "/api/tasks" && method === "GET") {
    const decoded = verifyToken(req);
    if (!decoded) return sendJSON(res, 401, { error: "Unauthorized" });
    return sendJSON(res, 200, { tasks: readJSON(tasksFile) });
  }

  if (pathname === "/api/tasks" && method === "POST") {
    const decoded = verifyToken(req);
    if (!decoded) return sendJSON(res, 401, { error: "Unauthorized" });
    const { title, description, projectId, priority, status } = await parseBody(req);
    const tasks = readJSON(tasksFile);
    const newTask = {
      id: Date.now(),
      title,
      description,
      projectId,
      priority: priority || "Medium",
      status: status || "todo",
      createdAt: new Date().toISOString(),
    };
    tasks.push(newTask);
    writeJSON(tasksFile, tasks);
    return sendJSON(res, 201, { task: newTask });
  }

  sendJSON(res, 404, { error: "Route not found" });
});

server.listen(PORT, () => console.log(`✅ Node.js server running at http://localhost:${PORT}`));
