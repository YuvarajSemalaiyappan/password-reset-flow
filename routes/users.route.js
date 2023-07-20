import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

import {
  addUser,
  getUserByUsername,
  updateUserByemail,
} from "../services/users.service.js";

const clienturl =  "http://localhost:3001";

 // "https://celadon-unicorn-ce7898.netlify.app";

const router = express.Router();

async function generateHashedPassword(password) {
  const salt = await bcrypt.genSalt(10);
  if (!salt) {
    throw new Error("Salt generation failed");
  }

  const hashedPassword = await bcrypt.hash(password, salt); // Corrected the parameter name here
  if (!hashedPassword) {
    throw new Error("Password hashing failed");
  }

  return hashedPassword;
}

router.post("/register", async function (req, res) {
  try {
    const userFromDB = await getUserByUsername(req.body.email);

    if (userFromDB) {
      res.status(200).send({ message: "username already exist try others" });
    } else if (!req.body.password1 || req.body.password1.length < 8) {
      res.status(400).send({ message: "password min 8 characters required" });
    } else {
      req.body.password1 = await generateHashedPassword(req.body.password1);
      delete req.body.password2;

      // console.log(req.body.password1);

      await addUser(req.body); //imported from service file

      res.send({ message: "Register successful" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: "something went wrong" });
  }
});

router.post("/login", async function (req, res) {
  try {
    const user = await getUserByUsername(req.body.email);
    if (user) {
      const match = await bcrypt.compare(req.body.password, user.password1);

      if (match) {
        const token = jwt.sign(
          { _id: user._id, name: user.email },
          process.env.SECRET_KEY
        );

        res.status(200).json({
          message: "Successfully Logged in",
          token: token,
          email: user.email,

          name: user.username,
        });
      } else {
        res.json({ message: "Invalid credentials" });
      }
    } else {
      res.json({ message: "User not found" });
    }
  } catch (error) {
    console.log(error);
  }
});

router.post("/sendmail", async function (request, response) {
  try {
    const email = request.body.email;
    const user = await getUserByUsername(email);

    if (user) {
      let transporter = nodemailer.createTransport({
        service: "gmail",
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD,
        },
      });
      var mailOptions = {
        from: process.env.EMAIL,
        to: user.email,
        subject: "Reset the password",
        text: "Hi",
        html: `<h1>User ${user.username} <a href="${clienturl}/changepassword/${user.email}">Please click here to reset the password</a> </h1>`,
      };
      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
        } else {
          console.log("Email sent: " + info.response);
        }
      });

      response.json({ message: "check your email" });
    } else {
      response.status(500).json({ message: "User not found" });
    }
  } catch (e) {
    console.log("Error: " + e.message);
  }
});

router.post("/changepassword/:email", async function (request, response) {
  try {
    let { password1 } = request.body;
    const { email } = request.params;
    const hashedPassword = await generateHashedPassword(password1);
    password1 = hashedPassword;
    
    delete request.body.password2;

    const result = await updateUserByemail({ email, password1 });
    if (result) {
      response.json({ message: "Reset the password successfully" });
    } else {
      response.json({ message: "Something went wrong" });
    }
  } catch (error) {
    console.log(error);
  }
});

export default router;
