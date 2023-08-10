
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');

const app = express();
const bcrypt = require('bcrypt');
const saltRounds = 10;
const db = new sqlite3.Database('./database2.db');

app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: 'mysecret', resave: false, saveUninitialized: false }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

///TEMP CODE Remove Prod
db.serialize(() => {
  db.run("DROP TABLE IF EXISTS ausbildungPlanDetails");
  db.run("DROP TABLE IF EXISTS ausbildungPlan");
  db.run("DROP TABLE IF EXISTS users");
  db.run("DROP TABLE IF EXISTS roles");
  db.run("DROP TABLE IF EXISTS permissions");
  db.run("DROP TABLE IF EXISTS role_permissions");
});

// Initiale Anlegen der Datenbank und Tabellen
db.serialize(() => {
  // Rollen
  db.run(`
      CREATE TABLE IF NOT EXISTS roles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE
      )
  `);

  // Berechtigungen
  db.run(`
      CREATE TABLE IF NOT EXISTS permissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE
      )
  `);

  // Rollen-Berechtigungen
  db.run(`
      CREATE TABLE IF NOT EXISTS role_permissions (
          roleId INTEGER NOT NULL,
          permissionId INTEGER NOT NULL,
          FOREIGN KEY (roleId) REFERENCES roles(id),
          FOREIGN KEY (permissionId) REFERENCES permissions(id),
          UNIQUE (roleId, permissionId)
      )
  `);

  // Benutzer-Rollen
  db.run(`
      CREATE TABLE IF NOT EXISTS user_roles (
          userId INTEGER NOT NULL,
          roleId INTEGER NOT NULL,
          FOREIGN KEY (userId) REFERENCES users(id),
          FOREIGN KEY (roleId) REFERENCES roles(id),
          UNIQUE (userId, roleId)
      )
  `);

  // Benutzer
  db.run(`
      CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL,
          roleId INTEGER,
          FOREIGN KEY (roleId) REFERENCES roles(id)
      )
  `);

  // Ausbildungspläne
  db.run(`
      CREATE TABLE IF NOT EXISTS ausbildungPlan (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          userId INTEGER NOT NULL,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          date TEXT NOT NULL,
          FOREIGN KEY (userId) REFERENCES users(id)
      )
  `);

  // Details der Ausbildungspläne
  db.run(`
      CREATE TABLE IF NOT EXISTS ausbildungPlanDetails (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ausbildungPlanId INTEGER NOT NULL,
          laufnummer TEXT NOT NULL,
          abschnitt TEXT NOT NULL,
          beschreibung TEXT NOT NULL,
          beispiele TEXT NOT NULL,
          lehrjahr TEXT NOT NULL,
          zeitraumVon TEXT NOT NULL,
          zeitraumBis TEXT NOT NULL,
          abteilung TEXT NOT NULL,
          mitarbeiter TEXT NOT NULL,
          FOREIGN KEY (ausbildungPlanId) REFERENCES ausbildungPlan(id)
      )
  `);
});



// Middleware to check if the user is logged in
const requireLogin = (req, res, next) => {
  if (!req.session.userId) {
      return res.redirect('/login');
  }
  next();
};

// Middleware to check if the user has a specific permission
function requirePermission(permissionName) {
  return (req, res, next) => {
      const userId = req.session.userId;
      if (!userId) {
          return res.redirect('/login');
      }

      const sql = `
          SELECT p.name 
          FROM permissions p
          JOIN role_permissions rp ON p.id = rp.permissionId
          JOIN roles r ON r.id = rp.roleId
          JOIN users u ON u.roleId = r.id
          WHERE u.id = ? AND p.name = ?
      `;

      db.get(sql, [userId, permissionName], (err, permission) => {
          if (err) {
              return res.status(500).send(err.message);
          }

          if (!permission) {
              return res.status(403).send('Access Denied');
          }

          next();
      });
  };
}


function logUserPermissions(req, res, next) {
  const userId = req.session.userId;
  if (!userId) {
      console.log("User is not logged in.");
      return next();
  }

  const sql = `
      SELECT p.name AS permissionName
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permissionId
      JOIN roles r ON r.id = rp.roleId
      JOIN users u ON u.roleId = r.id
      WHERE u.id = ?
  `;

  db.all(sql, [userId], (err, permissions) => {
      if (err) {
          console.error("Error fetching permissions:", err.message);
          return next();
      }

      console.log("User permissions:", permissions.map(p => p.permissionName));
      next();
  });
}

app.use(logUserPermissions);



// Middleware to fetch the role name for the current user
const fetchRoleName = (req, res, next) => {
  if (!req.session.userId) {
      res.locals.roleName = null;
      return next();
  }

  const sql = `
      SELECT r.name as roleName 
      FROM users u 
      JOIN roles r ON u.roleId = r.id 
      WHERE u.id = ?
  `;

  db.get(sql, [req.session.userId], (err, result) => {
      if (err) {
          return res.status(500).send(err);
      }
      
      res.locals.roleName = result ? result.roleName : null;
      next();
  });
};





// Middleware to require a specific role
const requireRole = (role) => {
  return (req, res, next) => {
      const userId = req.session.userId;
      if (!userId) {
          return res.redirect('/login');
      }
      const sql = `
          SELECT r.name as roleName 
          FROM users u 
          JOIN user_roles ur ON u.id = ur.userId
          JOIN roles r ON ur.roleId = r.id 
          WHERE u.id = ?
      `;
      db.get(sql, [userId], (err, row) => {
          if (err || !row || row.roleName !== role) {
              return res.status(403).send('Access Denied');
          }
          next();
      });
  };
};

// Function to generate a random password
function generateRandomPassword(length = 8) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let password = "";
  for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
  }
  return password;
}

const adminPassword = generateRandomPassword();

  bcrypt.hash(adminPassword, saltRounds, (err, hashedPassword) => {
    if (err) {
        console.error("Error hashing password:", err.message);
        return;
    }
    

    // Überprüfen, ob der Admin-Benutzer existiert
    db.get("SELECT id FROM users WHERE username = 'Admin'", [], (err, user) => {
        if (err) {
            console.error("Error checking Admin user:", err.message);
            return;
        }

        if (user) {
            // Admin-Benutzer existiert, Passwort aktualisieren
            db.run("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, user.id], (err) => {
                if (err) {
                    console.error("Error updating Admin password:", err.message);
                } else {
                    console.log("Admin password has been reset to:", adminPassword);
                }
            });
        } else {
            // Admin-Benutzer existiert nicht, Benutzer erstellen
            db.run("INSERT INTO users (username, password, roleId) VALUES (?, ?, (SELECT id FROM roles WHERE name = 'Administrator'))", ['Admin', hashedPassword], (err) => {
                if (err) {
                    console.error("Error creating Admin user:", err.message);
                } else {
                    console.log("Admin user has been created with password:", adminPassword);
                }
            });
        }
    });
});

function getUserPermissions(userId, callback) {
  const sql = `
      SELECT p.name 
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permissionId
      JOIN users u ON u.roleId = rp.roleId
      WHERE u.id = ?
  `;

  db.all(sql, [userId], (err, permissions) => {
      if (err) {
          return callback(err);
      }

      const permissionNames = permissions.map(p => p.name);
      callback(null, permissionNames);
  });
}

// Fügt Permissions in die Tabelle ein, wenn sie noch nicht existieren
const defaultPermissions = ['View', 'Edit', 'ManageRoles']; // Fügen Sie hier weitere standardmäßige Permissions hinzu
defaultPermissions.forEach(permission => {
    db.run(`INSERT OR IGNORE INTO permissions (name) VALUES (?)`, [permission], (err) => {
        if (err) {
            console.error(`Error inserting permission ${permission}:`, err.message);
        }
    });
});

// Function to assign all permissions to the Admin role
function assignAllPermissionsToAdmin(callback) {
  // Zuerst die ID des Admins abrufen
  db.get("SELECT id FROM users WHERE username = 'Admin'", (err, user) => {
      if (err || !user) {
          return callback(new Error("Admin user not found."));
      }

      const adminId = user.id;

      // Dann die ID der Rolle "Administrator" abrufen
      db.get("SELECT id FROM roles WHERE name = 'Administrator'", (err, role) => {
          if (err || !role) {
              return callback(new Error("Administrator role not found."));
          }

          const adminRoleId = role.id;

          // Alle verfügbaren Berechtigungen abrufen
          db.all("SELECT id FROM permissions", [], (err, permissions) => {
              if (err) {
                  return callback(err);
              }

              // Für jede Berechtigung, füge einen Eintrag in role_permissions hinzu, wenn er noch nicht existiert
              permissions.forEach(permission => {
                  const sql = `
                      INSERT OR IGNORE INTO role_permissions (roleId, permissionId)
                      VALUES (?, ?)
                  `;
                  db.run(sql, [adminRoleId, permission.id], (err) => {
                      if (err) {
                          console.error(`Error assigning permission ${permission.id} to Admin:`, err.message);
                      }
                  });
              });

              callback(null, "All permissions have been assigned to Admin.");
          });
      });
  });
}




function ensurePermissionsExist(req, res, next) {
  // Liste der Views, für die Permissions erstellt werden sollen
  const views = ['dashboard', 'manageRoles', 'managePermissions', 'assignRole']; // Fügen Sie hier alle Ihre Views hinzu

  views.forEach(view => {
      // Für jede View zwei Permissions erstellen: View und Edit
      const permissions = [`${view}View`, `${view}Edit`];

      permissions.forEach(permission => {
          // Überprüfen, ob die Permission bereits existiert
          db.get("SELECT id FROM permissions WHERE name = ?", [permission], (err, result) => {
              if (err) {
                  console.error("Error checking permission:", err.message);
                  return;
              }

              // Wenn die Permission nicht existiert, erstellen Sie sie
              if (!result) {
                  db.run("INSERT INTO permissions (name) VALUES (?)", [permission], (err) => {
                      if (err) {
                          console.error("Error inserting permission:", err.message);
                      }
                  });
              }
          });
      });
  });

  next(); // Fortfahren mit der nächsten Middleware oder Route
}


app.use(ensurePermissionsExist);
app.use(fetchRoleName);


// Homepage
app.get('/', (req, res) => {
  res.render('index', { userId: req.session.userId });
});

// Login
app.get('/login', (req, res) => {
  res.render('index');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
 
  
  assignAllPermissionsToAdmin((err, message) => {
    if (err) {
        console.error("Error assigning permissions to Admin:", err.message);
    } else {
        console.log(message);
    }
  });

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).send("Database error: " + err.message);
    }

    if (!user) {
      return res.status(401).send("Incorrect username or password");
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(500).send("Error checking password: " + err.message);
      }

      if (result) {
        req.session.userId = user.id;
        req.session.roleId = user.roleId;
        req.session.roleName = user.roleName;
        req.session.UserName = user.UserName;
        return res.redirect('/dashboard');
      } else {
        return res.status(401).send("Incorrect username or password");
      }
    });
  });
});

// Fügt Rollen in die Tabelle ein, wenn sie noch nicht existieren
const roles = ['Azubi', 'Ausbildungsbeauftragter', 'Ausbilder', 'HR', 'Administrator'];
roles.forEach(role => {
    db.run(`INSERT OR IGNORE INTO roles (name) VALUES (?)`, [role], (err) => {
        if (err) {
            console.error(`Error inserting role ${role}:`, err.message);
        }
    });
});




// Register


app.post('/register', (req, res) => {
  const { username, password } = req.body;

  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      return res.status(500).send("Error hashing password: " + err.message);
    }

    // Zuerst die ID der Rolle "Azubi" abrufen
    db.get("SELECT id FROM roles WHERE name = 'Azubi'", (err, role) => {
      if (err || !role) {
        return res.status(500).send("Error fetching Azubi role: " + err.message);
      }

      // Dann den neuen Benutzer mit der Rolle "Azubi" in die Datenbank einfügen
      const insertUser = db.prepare("INSERT INTO users (username, password, roleId) VALUES (?, ?, ?)");
      insertUser.run(username, hashedPassword, role.id, function(err) {
        if (err) {
          return res.status(500).send("Error registering user: " + err.message);
        }
        req.session.userId = this.lastID;
        res.redirect('/dashboard');
      });
    });
  });
});

app.get('/register', (req, res) => {
  res.render('register');
});



app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error during logout: " + err.message);
    }
    res.redirect('/');
  });
});


app.get('/dashboard', requireLogin, (req, res) => {
  const userId = req.session.userId;
  app.use(ensurePermissionsExist);
  console.log(res.locals.roleName);
  // Zuerst die ID der Rolle "Azubi" abrufen
  db.get("SELECT id FROM roles WHERE name = 'Azubi'", (err, role) => {
      if (err || !role) {
          console.error("Error fetching Azubi role:", err ? err.message : "Role not found");
          return res.status(500).send("Error fetching Azubi role");
      }

      // Dann Benutzer mit der Rolle "Azubi" abrufen
      db.all("SELECT * FROM users WHERE roleId = ?", [role.id], (err, azubis) => {
          if (err) {
              console.error("Error fetching Azubis:", err.message);
              return res.status(500).send("Error fetching Azubis");
          }

          // Alle Benutzer abrufen
          db.all('SELECT * FROM users', [], (err, users) => {
              if (err) {
                  return res.status(500).send(err);
              }

              // Ausbildungspläne des aktuellen Benutzers abrufen
              db.all('SELECT * FROM ausbildungPlan WHERE userId = ?', [userId], (err, ausbildungPlan) => {
                  if (err) {
                      return res.status(500).send(err);
                  }

                  // Berechtigungen des aktuellen Benutzers abrufen
                  getUserPermissions(userId, (err, permissions) => {
                      if (err) {
                          return res.status(500).send("Error fetching permissions: " + err.message);
                      }

                      res.render('dashboard', {
                          azubis: azubis,
                          userId: req.session.userId,
                          users: users,
                          roleID: req.session.roleId,
                          roleName: res.locals.roleName,
                          ausbildungPlan: ausbildungPlan,
                          permissions: permissions
                      });
                  });
              });
          });
      });
  });
});




// Create a new Ausbildungplan
app.post('/ausbildungPlan', requireLogin, (req, res) => {
  app.use(ensurePermissionsExist);
  const userId = req.session.userId;
  const title = req.body.title; // Azubi name
  const description = req.body.description; // Ausbildungsberuf
  const date = req.body.ausbildungBeginn;


  const sql = `INSERT INTO ausbildungPlan (userId, title, description, date) VALUES (?, ?, ?, ?)`;
  db.run(sql, [userId, title, description, date], function(err) {
    if (err) {
      return res.status(500).send("Error inserting into database: " + err.message);
    }
    res.redirect('/dashboard');
});
});

// Edit Ausbildungplan
app.get('/ausbildungPlan/:id/edit', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const ausbildungPlanId = req.params.id;
  const date = req.body.ausbildungBeginn;

  db.get('SELECT * FROM ausbildungPlan WHERE id = ? AND userId = ?', [ausbildungPlanId, userId], (err, plan) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (!plan) {
      return res.status(404).send({ message: 'Ausbildungsplan not found' });
    }
    db.all('SELECT * FROM ausbildungPlanDetails WHERE ausbildungPlanId = ?', [plan.id], (err, details) => {
      if (err) {
        return res.status(500).send(err);
      }
      res.render('edit', { userId: req.session.userId, plan, details });
    });
  });
});

// Add Detail to Ausbildungplan
app.post('/ausbildungPlan/:id/details', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const ausbildungPlanId = req.params.id;
  const { laufnummer, abschnitt, beschreibung, beispiele, lehrjahr, zeitraumVon, zeitraumBis, abteilung, mitarbeiter } = req.body;

  const sql = `
    INSERT INTO ausbildungPlanDetails (ausbildungPlanId, laufnummer, abschnitt, beschreibung, beispiele, lehrjahr, zeitraumVon, zeitraumBis, abteilung, mitarbeiter)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.run(sql, [ausbildungPlanId, laufnummer, abschnitt, beschreibung, beispiele, lehrjahr, zeitraumVon, zeitraumBis, abteilung, mitarbeiter], function(err) {
    if (err) {
      return res.status(500).send("Error inserting into database: " + err.message);
    }
    res.redirect('/ausbildungPlan/' + ausbildungPlanId + '/edit');
  });
});


app.get('/allusers', (req, res) => {
  app.use(ensurePermissionsExist);
  db.all('SELECT * FROM users', [], (err, users) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.json(users);
  });
});

app.get('/allausbildungsplan', (req, res) => {
  app.use(ensurePermissionsExist);
  db.all('SELECT * FROM ausbildungPlan', [], (err, users) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.json(users);
  });
});


app.get('/allroles', (req, res) => {
  app.use(ensurePermissionsExist);
  db.all('SELECT * FROM roles', [], (err, users) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.json(users);
  });
});

app.get('/assignRole', requireLogin, (req, res) => {
  app.use(ensurePermissionsExist);
  const sqlUsers = "SELECT id, username FROM users";
  const sqlRoles = "SELECT id, name FROM roles";

  db.all(sqlUsers, [], (err, users) => {
      if (err) {
          return res.status(500).send(err.message);
      }

      db.all(sqlRoles, [], (err, roles) => {
          if (err) {
              return res.status(500).send(err.message);
          }

          res.render('assignRole', { users: users, roles: roles });
      });
  });
});

app.post('/assignRole', requireLogin, (req, res) => {
  app.use(ensurePermissionsExist);
  const { userId, roleId } = req.body;
  const sql = "UPDATE users SET roleId = ? WHERE id = ?";

  db.run(sql, [roleId, userId], function(err) {
      if (err) {
          return res.status(500).send("Error updating user role: " + err.message);
      }
      res.redirect('/assignRole'); // oder wohin auch immer Sie den Benutzer nach der Rollenzuweisung umleiten möchten
  });
});

app.get('/managePermissions', requireLogin, (req, res) => {
  app.use(ensurePermissionsExist);
  const sqlRoles = "SELECT id, name FROM roles";
  const sqlPermissions = "SELECT id, name FROM permissions";
  const sqlRolePermissions = `
      SELECT r.name as roleName, p.name as permissionName 
      FROM role_permissions rp 
      JOIN roles r ON rp.roleId = r.id 
      JOIN permissions p ON rp.permissionId = p.id
  `;

  db.all(sqlRoles, [], (err, roles) => {
      if (err) {
          return res.status(500).send(err.message);
      }

      db.all(sqlPermissions, [], (err, permissions) => {
          if (err) {
              return res.status(500).send(err.message);
          }

          db.all(sqlRolePermissions, [], (err, rolePermissions) => {
              if (err) {
                  return res.status(500).send(err.message);
              }

              res.render('managePermissions', {
                  roles: roles,
                  permissions: permissions,
                  rolePermissions: rolePermissions
              });
          });
      });
  });
});



// Add New Permission
app.post('/addPermission', requireLogin, requireRole('Administrator'), (req, res) => {
  app.use(ensurePermissionsExist);
  const permissionName = req.body.permissionName;
  const sql = "INSERT INTO permissions (name) VALUES (?)";

  db.run(sql, [permissionName], (err) => {
      if (err) {
          return res.status(500).send("Error adding permission: " + err.message);
      }
      res.redirect('/managePermissions');
  });
});

// Assign Permission to Role
app.post('/assignPermissionToRole', requireLogin, requireRole('Administrator'), (req, res) => {
  app.use(ensurePermissionsExist);
  const { roleId, permissionId } = req.body;
  const sql = "INSERT INTO role_permissions (roleId, permissionId) VALUES (?, ?)";

  db.run(sql, [roleId, permissionId], (err) => {
      if (err) {
          return res.status(500).send("Error assigning permission to role: " + err.message);
      }
      res.redirect('/managePermissions');
  });
});


// Display Edit Permission Form
app.get('/editPermission/:id', requireLogin, requireRole('Administrator'), (req, res) => {
  const permissionId = req.params.id;
  const sqlPermission = "SELECT * FROM permissions WHERE id = ?";
  const sqlAllPermissions = "SELECT * FROM permissions";
  const sqlRoles = "SELECT * FROM roles";

  db.get(sqlPermission, [permissionId], (err, editingPermission) => {
      if (err) {
          return res.status(500).send(err.message);
      }

      db.all(sqlAllPermissions, [], (err, permissions) => {
          if (err) {
              return res.status(500).send(err.message);
          }

          db.all(sqlRoles, [], (err, roles) => {
              if (err) {
                  return res.status(500).send(err.message);
              }

              res.render('managePermissions', { permissions: permissions, roles: roles, editingPermission: editingPermission });
          });
      });
  });
});

// Update Permission in Database
app.post('/editPermission/:id', requireLogin, requireRole('Administrator'), (req, res) => {
  const permissionId = req.params.id;
  const updatedPermissionName = req.body.permissionName;
  const sql = "UPDATE permissions SET name = ? WHERE id = ?";

  db.run(sql, [updatedPermissionName, permissionId], (err) => {
      if (err) {
          return res.status(500).send("Error updating permission: " + err.message);
      }
      res.redirect('/managePermissions');
  });
});

app.get('/addPermission', requireLogin, requireRole('Administrator'), (req, res) => {
  res.render('addPermission');
});

app.get('/editPermission', requireLogin, requireRole('Administrator'), (req, res) => {
  db.all('SELECT * FROM permissions', [], (err, permissions) => {
      if (err) {
          return res.status(500).send(err);
      }
      res.render('editPermission', { permissions: permissions });
  });
});

app.post('/editPermission', requireLogin, requireRole('Administrator'), (req, res) => {
  app.use(ensurePermissionsExist);
  const { permissionId, newPermissionName } = req.body;
  db.run("UPDATE permissions SET name = ? WHERE id = ?", [newPermissionName, permissionId], (err) => {
      if (err) {
          return res.status(500).send("Error updating permission: " + err.message);
      }
      res.redirect('/managePermissions');
  });
});
app.get('/rolePermissions', requireLogin, requirePermission('ManageRoles'), (req, res) => {
  app.use(ensurePermissionsExist);
  const sqlRoles = "SELECT * FROM roles";
  const sqlPermissions = "SELECT * FROM permissions";

  db.all(sqlRoles, [], (err, roles) => {
      if (err) {
          return res.status(500).send(err.message);
      }

      db.all(sqlPermissions, [], (err, permissions) => {
          if (err) {
              return res.status(500).send(err.message);
          }

          // Für den Anfang nehmen wir die Berechtigungen der ersten Rolle
          const firstRoleId = roles[0].id;
          const sqlRolePermissions = "SELECT permissionId FROM role_permissions WHERE roleId = ?";

          db.all(sqlRolePermissions, [firstRoleId], (err, rolePermissions) => {
              if (err) {
                  return res.status(500).send(err.message);
              }

              const permissionIds = rolePermissions.map(rp => rp.permissionId);
              res.render('rolePermissions', {
                  roles: roles,
                  permissions: permissions,
                  rolePermissions: permissionIds
              });
          });
      });
  });
});
app.post('/updateRolePermissions', requireLogin, requirePermission('ManageRoles'), (req, res) => {
  const roleId = req.body.roleId;
  const permissionIds = req.body.permissionIds || [];

  // Alle aktuellen Berechtigungen der Rolle löschen
  db.run("DELETE FROM role_permissions WHERE roleId = ?", [roleId], (err) => {
      if (err) {
          return res.status(500).send(err.message);
      }

      // Neue Berechtigungen hinzufügen
      const insert = db.prepare("INSERT INTO role_permissions (roleId, permissionId) VALUES (?, ?)");
      permissionIds.forEach(permissionId => {
          insert.run(roleId, permissionId);
      });

      insert.finalize(() => {
          res.redirect('/rolePermissions');
      });
  });
});


app.get('/checkUsername/:username', (req, res) => {
  const username = req.params.username;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
      if (err) {
          return res.status(500).send("Database error: " + err.message);
      }
      if (user) {
          return res.json({ exists: true });
      } else {
          return res.json({ exists: false });
      }
  });
});

app.get('/assignAllPermissionsToAdmin', (req, res) => {
  assignAllPermissionsToAdmin((err, message) => {
      if (err) {
          console.error("Error assigning permissions:", err.message);
          return res.status(500).send("Failed to assign permissions to Admin.");
      }
      res.send(message);
  });
});




app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
