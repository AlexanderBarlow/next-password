const sequelize = require("../config/connection");
const seedUsers = require("./seed");

const seedAll = async () => {
  await sequelize.sync({ force: true });

  await seedUsers();

  process.exit(0);
};

// module.exports = seedAll;
seedAll();