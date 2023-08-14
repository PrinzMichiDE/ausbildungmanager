module.exports = (sequelize, DataTypes) => {
    const Role = sequelize.define('Role', {
        name: {
            type: DataTypes.STRING,
            unique: true,
            allowNull: false
        }
    });
    return Role;
};
