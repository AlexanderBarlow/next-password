import { NextApiRequest, NextApiResponse } from "next";
import { User } from "../../../models"; 

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  try {
    if (req.method === "GET") {
      if (req.query.action === "username") {
        // You can perform some logic here or send a response indicating the 'username' action
        res
          .status(200)
          .json({ message: "Render username view on the client side" });
      } else if (req.query.action === "password") {
        // You can perform some logic here or send a response indicating the 'password' action
        res
          .status(200)
          .json({ message: "Render password view on the client side" });
      } else {
        // Fetch all users from the database
        console.log("Admin Route")
        const allUsers = await User.findAll();

        // Respond with the list of users as JSON
        res.status(200).json(allUsers);
        console.log(allUsers);
      }
    } else if (req.method === "POST" && req.query.action === "createuser") {
      const userData = await User.create(req.body);

      res.status(200).json(userData);
    } else {
      // Handle other HTTP methods or invalid actions
      res.status(405).json({ message: "Method Not Allowed" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}
