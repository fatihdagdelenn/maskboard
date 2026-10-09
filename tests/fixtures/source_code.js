const os = require("os");

function connect(cfg) {
  const host = cfg.host || process.env.DB_HOST;
  const user = this.user;
  const password = readSecret("db");
  const token = options.token;
  const db = createPool({ host: host, user: user, password: password });
  return db;
}

const config = {
  host: "web07.corp.local",
  user: "deploy_bot",
  password: "Spring.2026q",
  database: "orders_prod",
};
