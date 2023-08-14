const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
    const User = sequelize.define('User', {
        username: {
            type: DataTypes.STRING,
            unique: true,
            allowNull: false
        },
        password: {
            type: DataTypes.STRING,
            allowNull: false
        },
        tenantId: {
            type: DataTypes.STRING,
            allowNull: false
        },
        RoleId: {
            type: DataTypes.STRING,
            allowNull: false
        }        
    });
 
    return User;
};
