const mysql = require('mysql2');

const pool = mysql.createPool({
  user: 'test1',
  password: 'test1',
  database: 'my_db',
  port: 3306,
});

module.exports = pool.promise();
