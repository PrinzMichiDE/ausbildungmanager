'use strict';

const fs = require('fs');
const path = require('path');
const Sequelize = require('sequelize');
const process = require('process');
const basename = path.basename(__filename);
const env = process.env.NODE_ENV || 'development';
const config = require(__dirname + '/../config/config.js')[env];
const db = {};

console.log('Initializing Sequelize...');

let sequelize;
try {
    sequelize = new Sequelize(config.database, config.username, config.password, config);
    console.log('Sequelize initialized successfully.');
} catch (error) {
    console.error('Error initializing Sequelize:', error);
}

// Importieren der Modelle
console.log('Importing models...');

// Importieren der Modelle
//const User = require('./user')(sequelize, Sequelize.DataTypes);
//const Tenant = require('./tenant')(sequelize, Sequelize.DataTypes);
//const Role = require('./role')(sequelize, Sequelize.DataTypes); // Neues Modell



let User, Tenant, Role;

try {
  Role = require('./role')(sequelize, Sequelize.DataTypes);  // Importieren und Initialisieren des Tenant-Modells
  console.log('Role model imported successfully.');

  Tenant = require('./tenant')(sequelize, Sequelize.DataTypes);  // Importieren und Initialisieren des Tenant-Modells
  console.log('Tenant model imported successfully.');



    User = require('./user')(sequelize, Sequelize.DataTypes);  // Importieren und Initialisieren des User-Modells
    console.log('User model imported successfully.');


} catch (error) {
    console.error('Error importing models:', error);
}


// Definieren der Beziehungen
//User.belongsTo(Role); // Ein Benutzer gehört zu einer Rolle
//Role.hasMany(User);   // Eine Rolle kann vielen Benutzern zugewiesen werden

module.exports = {
    sequelize,
    Sequelize,
    User,
    Tenant,
    Role
};

console.log('Models exported successfully.');
