const mysql = require('mysql2/promise'); // Using the mysql2 package for MySQL
require('dotenv').config();

// Load database credentials and settings from .env
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
};

// Create a connection pool
const pool = mysql.createPool(dbConfig);

module.exports = pool;
