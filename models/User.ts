import { Model, DataTypes } from "sequelize";
import bcrypt from "bcrypt";
import sequelize from "../config/connection";

interface UserAttributes {
  id?: number;
  user_name: string;
  user_password: string;
}

class User extends Model<UserAttributes> {
  public id!: number;
  public user_name!: string;
  public user_password!: string;

  checkPassword(loginPw: string): boolean {
    return bcrypt.compareSync(loginPw, this.user_password);
  }
}

User.init(
  {
    id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true,
      autoIncrement: true,
    },
    user_name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    user_password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [8, Infinity],
          msg: "Password must be at least 8 characters long",
        },
      },
    },
  },
  {
    hooks: {
      beforeCreate: async (newUserData: User): Promise<void> => {
        newUserData.user_password = await bcrypt.hash(
          newUserData.user_password,
          10,
        );
        return;
      },
    },
    sequelize,
    timestamps: false,
    freezeTableName: true,
    underscored: true,
    modelName: "user",
  },
);

export default User;
