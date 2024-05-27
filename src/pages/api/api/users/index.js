// pages/api/users.js

import { User } from "../../../../../models";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import session from "express-session";
import { serialize } from "cookie";

export default async function handler(req, res) {
  // Set up session middleware
  const sessionMiddleware = (req, res, next) => {
    session({
      secret: "123",
      resave: false,
      saveUninitialized: true,
      cookie: {
        maxAge: 3 * 60 * 60 * 1000,
      },
    })(req, res, next);
  };

  // Function to generate a session token
  function generateSessionToken(session) {
    return jwt.sign(
      {
        user_id: session.user_id,
        user_name: session.user_name,
        logged_in: session.logged_in,
      },
      "123",
      {
        expiresIn: "3h",
      }
    );
  }

  // Asserting the type here
  sessionMiddleware(req, res, async () => {
    try {
      if (req.method === "GET") {
        const userData = await User.findAll();
        return res.status(200).json(userData);
      } else if (req.method === "POST" && req.query.action === "login") {
        const body = req.body;
        const userData = await User.findOne({
          where: { user_name: body.userName },
        });

        if (!userData) {
          return res.status(400).json({
            message: "Incorrect username or password, please try again",
          });
        }

        req.session.user_id = userData.id;
        req.session.user_name = userData.user_name; // Store user_name in session
        req.session.logged_in = true;

        req.session.save((err) => {
          if (err) {
            console.error("Error saving session:", err);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          const token = generateSessionToken(req.session);

          const cookie = serialize("sessionToken", token, {
            maxAge: 3 * 60 * 60 * 1000,
            secure: process.env.NODE_ENV === "production",
            path: "/",
          });

          res.setHeader("Set-Cookie", cookie);
          return res.status(200).json(userData);
        });
      } else if (req.method === "POST") {
        const body = req.body;
        const userData = await User.create({
          user_name: body.userName,
          user_password: body.password,
        });

        if (!userData || userData instanceof Array) {
          console.error("Invalid user data:", userData);
          return res.status(500).json({ error: "User data is invalid." });
        }

        if (typeof userData.id === "undefined") {
          console.error("User data does not contain id:", userData);
          return res.status(500).json({ error: "User data is missing id." });
        }

        if (req.session) {
          req.session.user_id = userData.id;
          req.session.user_name = userData.user_name; // Store user_name in session
          req.session.logged_in = true;

          req.session.save((err) => {
            if (err) {
              console.error("Error saving session:", err);
              return res.status(500).json({ error: "Internal Server Error" });
            }

            const token = generateSessionToken(req.session);

            const cookie = serialize("sessionToken", token, {
              maxAge: 3 * 60 * 60 * 1000,
              secure: process.env.NODE_ENV === "production",
              path: "/",
            });

            res.setHeader("Set-Cookie", cookie);
            return res.status(200).json(userData);
          });
        }
      } else if (req.method === "PUT" && req.query.action === "updatep") {
        const { id, newPassword } = req.body;

        if (!id || !newPassword) {
          return res.status(400).json({
            error: "Invalid request. Please provide id and newPassword.",
          });
        }

        const user = await User.findByPk(id);

        if (!user) {
          return res.status(404).json({ error: "User not found." });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await user.update({ user_password: hashedPassword });

        return res.json({ message: "Password updated successfully." });
      } else if (req.method === "POST" && req.query.action === "logout") {
        req.session.destroy(() => {
          return res.status(204).end();
        });
      } else {
        return res.status(405).json({ error: "Method Not Allowed" });
      }
    } catch (error) {
      console.error("Error:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  });
}
