import { NextApiRequest, NextApiResponse } from "next";
import { User, Passwords } from "../../../../../models";
import jwt, { JwtPayload } from "jsonwebtoken";
import { Session } from "next-auth";

// Custom session type extending NextAuth's Session
interface CustomSession extends Session {
  logged_in?: boolean;
}

// Custom request type extending NextApiRequest with custom session type
interface CustomNextApiRequest extends NextApiRequest {
  session: CustomSession;
}

// Interface for decoded JWT token
interface DecodedToken {
  user_id?: number;
  logged_in?: boolean;
}

export default async function handler(
  req: CustomNextApiRequest,
  res: NextApiResponse,
) {
  try {
    if (req.method === "GET") {
      if (!req.session.logged_in) {
        res.redirect("/signup");
        return;
      } else {
        try {
          const passwordData = await Passwords.findAll();
          res.status(200).json(passwordData);
        } catch (err) {
          res.status(500).json(err);
        }
      }
    } else if (req.method === "GET" && req.query.id) {
      if (!req.session.logged_in) {
        res.redirect("/");
        return;
      } else {
        try {
          const passwordData = await Passwords.findByPk(
            req.query.id as string,
            {
              include: [
                {
                  model: User,
                  as: "user_passwords",
                },
              ],
            },
          );

          if (!passwordData) {
            res
              .status(404)
              .json({ message: "No password found with this id." });
            return;
          }

          res.status(200).json(passwordData);
        } catch (err) {
          res.status(500).json(err);
        }
      }
    } else if (req.method === "DELETE" && req.query.id) {
      const sessionToken = req.headers.authorization?.split(" ")[1];

      if (!sessionToken) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      try {
        // Decode the JWT with the proper type annotations
        const decodedToken: DecodedToken = jwt.verify(
          sessionToken,
          "123",
        ) as DecodedToken;

        // Check if the user is logged in
        if (!decodedToken.logged_in) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        // Now you have access to req.session.user_id
        const user_id = decodedToken.user_id;

        // Continue with your existing logic
        const passwordData = await Passwords.destroy({
          where: {
            id: req.query.id as string,
            user_id: user_id, // Ensure the user can only delete their own passwords
          },
        });

        if (!passwordData) {
          return res
            .status(404)
            .json({ error: "No Password found with this id." });
        }

        return res
          .status(200)
          .json({ message: "Password deleted successfully." });
      } catch (err) {
        console.error("Error during JWT verification:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }
    } else if (req.method === "PUT" && req.query.id) {
      console.log("update route");
      console.log(req.query.id);

      try {
        const updatedPassword = await Passwords.update(
          {
            password: req.body.password,
            title: req.body.title,
            username: req.body.username,
          },
          {
            where: {
              id: req.query.id as string,
            },
            individualHooks: true, // This ensures that only the specified fields are updated
          },
        );

        // updatedPassword is an array with the number of affected rows
        if (updatedPassword[0] > 0) {
          // Sends a success message as a json response
          res.json({ message: "Password updated successfully." });
        } else {
          res.status(404).json({ error: "Password not found." });
        }
      } catch (err) {
        console.error("Error updating password:", err);
        res.status(500).json({ error: "Internal Server Error" });
      }
    } else {
      // Handle other HTTP methods or invalid actions
      res.status(405).json({ error: "Method Not Allowed" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
