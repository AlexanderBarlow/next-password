// Convert CommonJS to ES module
import  User  from "./User";
import Passwords from "./Passwords";

User.hasMany(Passwords, {
  foreignKey: "user_id",
});

Passwords.belongsTo(User, {
  foreignKey: "user_id",
});

export { User, Passwords };
