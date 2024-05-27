// ES6 modules
import { Sequelize, Dialect } from "sequelize";

interface SequelizeOptions {
  dialect: Dialect;
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
  // Add other options as needed
}

let sequelize: Sequelize;

if (process.env.JAWSDB_URL) {
  // If the app is deployed, use the JawsDB connection URL
  sequelize = new Sequelize(process.env.JAWSDB_URL);
} else {
  // If not deployed, use the local connection parameters
  const localOptions: SequelizeOptions = {
    dialect: "mysql",
    host: process.env.DB_HOST || "localhost",
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
    username: process.env.DB_USER || "root",
    password: process.env.DB_PW || "Biteme1502",
    database: process.env.DB_NAME || "passwordtracker_db",
    // Add other options as needed
  };

  sequelize = new Sequelize(localOptions);
}

export default sequelize;
