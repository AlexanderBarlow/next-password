import { Passwords } from "../../../../models";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const handler = async (req, res) => {
  try {
    if (req.method === "GET" && req.query.action === "copy" && req.query.id) {
      const sessionToken = req.headers.authorization?.split(" ")[1];

      if (!sessionToken) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      try {
        const decodedToken = jwt.verify(sessionToken, "123");

        if (!decodedToken.logged_in) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        const user_id = decodedToken.user_id;

        const passwordDB = await Passwords.findOne({
          where: { user_id, id: req.query.id },
          attributes: [
            "id",
            "username",
            "user_id",
            "password",
            "title",
            "initVector",
            "securityKey",
          ],
        });

        if (!passwordDB) {
          return res.status(404).json({ error: "Password not found" });
        }

        const password = passwordDB.get({ plain: true });
        const securityKey = Buffer.from(password.securityKey, "hex");
        const initVector = Buffer.from(password.initVector, "hex");
        const encryptedData = password.password;
        const algorithm = "aes-256-cbc";

        const decipher = crypto.createDecipheriv(
          algorithm,
          securityKey,
          initVector
        );
        let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
        decryptedData += decipher.final("utf8");

        res.json({ decryptedData });
      } catch (error) {
        console.error("Error during JWT verification:", error);
        res.status(401).json({ error: "Unauthorized" });
      }
    } else if (req.method === "GET") {
      console.log("User Password route hit");

      const token = req.headers.authorization?.split(" ")[1];

      if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const decodedToken = jwt.verify(token, "123");

      const user_id = decodedToken.user_id;
      const session = decodedToken.logged_in;

      if (!session) {
        res.redirect("/");
        return;
      } else {
        console.log("DB Post");
        const passwordDB = await Passwords.findAll({
          where: { user_id },
          attributes: [
            "id",
            "username",
            "user_id",
            "password",
            "title",
            "initVector",
            "securityKey",
          ],
        });

        const passwords = passwordDB.map((password) =>
          password.get({ plain: true })
        );
        res.status(200).json({ passwords });
      }
    } else if (req.method === "GET" && req.query.action === "update") {
      res.json({ message: "Render update view on the client side" });
    } else if (req.method === "POST" && req.query.action === "new") {
      console.log("Password Route Hit", req.body);

      try {
        const sessionToken = req.cookies.sessionToken;
        const decodedToken = jwt.verify(sessionToken, "123");

        const algorithm = "aes-256-cbc";
        const initVector = crypto.randomBytes(16);
        const message = req.body.password;
        const securityKey = crypto.randomBytes(32);
        const cipher = crypto.createCipheriv(
          algorithm,
          securityKey,
          initVector
        );

        let encryptedData = cipher.update(message, "utf-8", "hex");
        encryptedData += cipher.final("hex");

        const newPassword = await Passwords.create({
          username: req.body.username,
          title: req.body.title,
          password: encryptedData,
          initVector: initVector.toString("hex"),
          securityKey: securityKey.toString("hex"),
          user_id: decodedToken.user_id,
        });

        return res.status(200).json(newPassword);
      } catch (err) {
        return res.status(400).json(err);
      }
    } else {
      return res.status(405).json({ error: "Method Not Allowed" });
    }
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

export default handler;
