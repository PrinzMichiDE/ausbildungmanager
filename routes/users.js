const express = require('express');
const bcrypt = require('bcryptjs');
const passport = require('passport');
console.log("Before importing models in users.js");
const { User, Tenant, Role } = require('../models');
console.log("After importing models in users.js");

//const { sequelize } = require('./models');


const router = express.Router();

function suggestTenantId(email) {
    const domain = email.split('@')[1];
    return domain.split('.')[0];
}


// Registrierung
router.post('/register', async (req, res) => {
    const chosenTenantId = req.body.tenantId;
    const existingTenant = await Tenant.findOne({ where: { id: chosenTenantId } });

    if (existingTenant) {
        // Zeigen Sie eine Fehlermeldung an, dass die tenantId bereits vergeben ist
        return res.status(400).send('Tenant ID already exists');
    }

    try {
        const existingUser = await User.findOne({ where: { username: req.body.username } });
        if (existingUser) {
            return res.status(400).send('Username already exists');
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        const existingUsersForTenant = await User.count({ where: { tenantId: chosenTenantId } });

        let roleName = 'Gast';
        if (existingUsersForTenant === 0) {
            roleName = 'Administrator';
        }

        const role = await Role.findOne({ where: { name: roleName } });

        const newUser = await User.create({
            username: req.body.username,
            password: hashedPassword,
            tenantId: chosenTenantId,
            RoleId : role
        });

        await newUser.setRole(role);  // Hier setzen wir die Rolle für den Benutzer

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Login
router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            req.flash('error', info.message);
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            // Setzen Sie hier den Mandanten in der Session
            req.session.tenantId = user.tenantId;
            return res.redirect('/dashboard');
        });
    })(req, res, next);
});



module.exports = router;
