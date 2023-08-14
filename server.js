require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { sequelize } = require('./models');
const { User } = require('./models');
const adminRoutes = require('./routes/admin');



const app = express();


// Middleware für das Parsen von POST-Anfragen
console.log("Setting up middleware...");
app.use(express.urlencoded({ extended: true }));

// Session-Konfiguration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Flash-Middleware für temporäre Nachrichten
app.use(flash());

// Passport-Initialisierung
app.use(passport.initialize());
app.use(passport.session());


function checkTenant(req, res, next) {
    if (!req.session.tenantId) {
        return res.status(403).send('Tenant not set');
    }
    next();
}

//app.use(checkTenant);

console.log("Middleware set up successfully.");

// Passport Lokale Strategie
passport.use(new LocalStrategy(
    async (username, password, done) => {
        console.log(`Attempting to find user with username: ${username}`);
        console.log(`Entered password: ${password}`);


        try {
            const user = await User.findOne({ where: { username: username } });

            if (!user) {
                console.log(`No user found with username: ${username}`);
                return done(null, false, { message: 'Incorrect username.' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                console.log("Entered password:", password);
                console.log("Stored password hash:", user.password);

                console.log("Password does not match.");
                return done(null, false, { message: 'Incorrect password.' });
            }

            console.log("User found and password matches. Authentication successful.");
            return done(null, user);
        } catch (err) {
            console.error("Error during user lookup:", err);
            return done(err);
        }
    }
));


passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findByPk(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});


// EJS und static files
app.set('view engine', 'ejs');
app.use(express.static('public'));


function requireRole(roleName) {
    return async (req, res, next) => {
        const user = req.user; // Angenommen, Sie haben den Benutzer bereits authentifiziert
        const roles = await user.getRoles({ where: { tenantId: req.session.tenantId } });
        if (roles.some(role => role.name === roleName)) {
            return next();
        } else {
            res.status(403).send('Zugriff verweigert');
        }
    };
}

function ensureAdmin(req, res, next) {
    if (req.user && req.user.role === 'Administrator') {
        return next();
    }
    res.status(403).send("Zugriff verweigert");
}


app.get('/', (req, res) => {
    res.render('index');
});
app.get('/login', (req, res) => {
    res.render('index');
});

app.get('/register', (req, res) => {
    res.render('register');
});



app.get('/roleManagement', ensureAdmin, async (req, res) => {
    try {
        const users = await User.findAll({ where: { tenantId: req.session.tenantId } });
        res.render('roleManagement', { users });
    } catch (error) {
        console.error("Fehler beim Abrufen der Benutzer:", error);
        res.status(500).send("Ein Fehler ist aufgetreten");
    }
});

app.post('/updateRole', ensureAdmin, async (req, res) => {
    try {
        const { userId, role: roleName } = req.body;
        
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).send("Benutzer nicht gefunden");
        }
        
        const role = await Role.findOne({ where: { name: roleName } });
        await user.setRoles([role]);
        
        res.redirect('/roleManagement');
    } catch (error) {
        console.error("Fehler beim Aktualisieren der Rolle:", error);
        res.status(500).send("Ein Fehler ist aufgetreten");
    }
});


app.use('/admin', adminRoutes);

const userRoutes = require('./routes/users');  // Pfad zu Ihrer Routendatei
app.use('/users', userRoutes);

// 404 Fehlerbehandlung
app.use((req, res, next) => {
    res.status(404).send('Seite nicht gefunden');
});

// Allgemeine Fehlerbehandlung
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Etwas ist schief gelaufen!');
});

sequelize.sync({ force: true });
const PORT = process.env.PORT || 3000;
sequelize.sync()  // Dies stellt sicher, dass alle definierten Modelle mit der Datenbank synchronisiert werden
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server läuft auf http://localhost:${PORT}`);
        });
    })
    .catch(err => {
        console.error('Fehler beim Verbinden mit der Datenbank:', err);
    });

