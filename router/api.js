const express = require("express");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const sanitize = require("mongo-sanitize");
const { promisify } = require("util");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const url = require("url");
require("dotenv").config();
const nodemailer = require("nodemailer");

const User = require("../models/adminSchema");

const unlinkAsync = promisify(fs.unlink);

// SET STORAGE
const storage = multer.diskStorage({
    destination(req, file, cb) {
        cb(null, "../daulatram/public/images/uploads");
    },
    filename(req, file, cb) {
        cb(null, `${new Date().getTime()}_${file.originalname}`);
    },
});
const upload = multer({
    storage: storage,
    limits: {
        // max file size 100MB = 100000000 bytes
        fileSize: 100000000,
    },
    fileFilter(req, file, cb) {
        if (!file.originalname.match(/\.(jpeg|jpg|png|pdf|doc|docx|xlsx|xls)$/)) {
            return cb(
                new Error(
                    "only upload files with jpg, jpeg, png, pdf, doc, docx, xslx, xls format."
                )
            );
        }
        cb(undefined, true);
    },
});

// Admin
router.get("/getdata", async (req, res) => {
    const details = await User.find();
    res.status(200).json(details);
});
router.get("/resetData", async (req, res) => {
    const tok = req.query.resetPasswordToken;

    const details = await User.findOne({
        resetPasswordToken: tok,
    });
    if (!details) {
        console.log("password reset link is invalid");
        res.status(400).json("password reset link is invalid");
    } else {
        const exp = details.resetPasswordExpires;
        const diff = exp - Date.now();
        // console.log(exp)

        if (diff > 0) {
            res.status(200).json({
                username: details.Username,
                message: "password reset link a-ok",
            });
        } else {
            // console.log('password reset link has expired')
            res.status(400).json("password reset link has expired");
        }
    }
});

router.put("/updatePasswordViaEmail", async (req, res) => {
    try {
        // 
        const { Username, Password } = req.body;

        const details = await User.findOne({
            Username: Username,
        });
        if (details) {
            const salt = await bcrypt.genSalt();

            // console.log('User exists in the database')
            const hashedPassword = await bcrypt.hash(Password, salt);
            const data = await details.updateOne({
                Password: hashedPassword,
                resetPasswordToken: null,
                resetPasswordExpires: null,
            });
            if (data) {
                // console.log('password updated');
                res.status(200).json({ message: "password updated" });
            } else {
                // console.log("Password can't be update")
                res.status(403).json("Password can't be update");
            }
        } else {
            // console.log('no user exists in db to update')
            res.status(404).json("no user exists in db to update");
        }
    } catch (err) {
        console.log("err");
    }
});

router.post("/NewAdmin", async (req, res) => {
    try {
        const salt = await bcrypt.genSalt();
        const { Username, Email, Password } = req.body;;

        if (!Username || !Email || !Password) {
            return res.status(400).json({ error: "Fill the complete form" });
        }
        // const hashedUser = await bcrypt.hash(Username, salt)
        const hashedPassword = await bcrypt.hash(Password, salt);

        const user = new User({
            Username: Username,
            Email: Email,
            Password: hashedPassword,
        });
        await user.save();
        // console.log("Form filled Successfully")
        return res.status(200).json({ message: "Form filled Successfully " });
    } catch (err) {
        console.log(err);
    }
});

router.post("/forgotEmail", async (req, res) => {
    try {
        const { Email } = req.body;
        if (!Email) {
            return res.status(400).json("email required");
        }
        const user = await User.findOne({ Email: Email });
        if (!user) {
            return res.status(401).json("email not in the database");
        } else {
            const token = crypto.randomBytes(20).toString("hex");
            const up = await user.updateOne({
                resetPasswordToken: token,
                resetPasswordExpires: Date.now() + 3600000,
            });
            if (up) {
                const transporter = nodemailer.createTransport({
                    service: "gmail",
                    auth: {
                        user: `${process.env.EMAIL_ADDRESS}`, // generated ethereal user
                        pass: `${process.env.EMAIL_PSSWD}`, // generated ethereal password
                    },
                });

                const mailOptions = {
                    from: ` "Recovery Email for Daulatram Admin" <${process.env.EMAIL_ADDRESS}>`,
                    to: `${Email}`,
                    Subject: "Link to Reset Password",
                    text: "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
                        "Please click on the following link, or paste this into your browser to complete the process within 10 mins of receiving it:\n\n" +
                        `http://localhost:3000/reset/${token}\n\n` +
                        `This link is valid only upto 10 mins\n\n` +
                        "If you did not request this, please ignore this email and your password will remain unchanged",
                };

                console.log("Sending email.....");

                transporter.sendMail(mailOptions, (err, response) => {
                    if (err) {
                        console.log("There was an error: ", err);
                    } else {
                        console.log("There you Go: ", response);
                        return res.status(200).json("Recovery email sent");
                    }
                });
            } else {
                console.log("Unable to give token ");
            }
        }
    } catch (err) {
        console.log(" External err");
    }
});

router.post("/AdminLogin", async (req, res) => {
    try {
        const { Username, Password } = req.body;
        if (!Username || !Password) {
            return res
                .status(400)
                .json({ error: "Fill the Admin Login Form Properly" });
        }
        const username_ = sanitize(Username);

        const UserLogin = await User.findOne({ Username: username_ });
        //   const UserLogin = await User.findOne({ Username: username_ })

        if (UserLogin) {
            const isMatch = await bcrypt.compare(Password, UserLogin.Password);
            // console.log(isMatch)
            if (!isMatch) {
                console.log("Invalid Credentials");
                res.status(402).json({ error: "Invalid Credentials" });
            } else {
                console.log("Signin Successful");
                res.status(200).json({ message: "user Signin Sucessfully" });
                await UserLogin.save();
            }
        } else {
            console.log("Login Failed");
            res.status(401).json({ error: "Login Failed" });
        }
    } catch (err) {
        console.log(err);
    }
});

router.delete("/delete/:id", async (req, res) => {
    const delete_user = await User.findOneAndDelete({ _id: req.params.id });
    res.send(delete_user + "User deleted");
});

module.exports = router;
