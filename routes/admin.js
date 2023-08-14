const express = require('express');
const router = express.Router();
const { sequelize } = require('../models');
const user = require('../models/user');
const { User } = require('../models');


router.get('/clear-database', async (req, res) => {
    try {
        // WARNUNG: Dies wird alle Daten in allen Tabellen löschen!
        await sequelize.sync({ force: true });
        res.send('Datenbank erfolgreich geleert.');
    } catch (err) {
        console.error(err);
        res.status(500).send('Fehler beim Leeren der Datenbank.');
    }
});

router.get('/all-users', async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'username', 'password']  // WARNUNG: Das Einschließen des Passworts ist unsicher!
        });
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).send('Fehler beim Abrufen der Benutzer.');
    }
});


module.exports = router;
