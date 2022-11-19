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

const unlinkAsync = promisify(fs.unlink);

// Admin 
const User = require("../models/adminSchema");

// About Us files
const Founder = require("../models/About_Us/Founder_Schema")
const Chairperson = require("../models/About_Us/Chairperson_Schema")
const Mission = require("../models/About_Us/Mission_Schema")
const Principal = require("../models/About_Us/Principal_Schema")
const VicePrincipal = require("../models/About_Us/VicePrincipal_Schema")
const Gallery_About = require("../models/About_Us/Gallery_About_Schema")
const About_Administration = require("../models/About_Us/About_Administration_Schema")

// Academics files
const Acad_Facilities = require("../models/Academics/Acad_Facilities_Schema")
const C_Acad_Cal = require("../models/Academics/C_Acad_Cal_Schema")
const U_Acad_Cal = require("../models/Academics/U_Acad_Cal_Schema")
const Teacher = require("../models/Academics/Teacher_Schema")
const Courses = require("../models/Academics/Courses_Schema")
const Resources_Innovation = require("../models/Academics/Resources_Innovation_Schema")
const Training = require("../models/Academics/Training_Schema")


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

// About Us Founder

router.get("/Founder_About", async (req, res) => {
    const details = await Founder.find();
    if (details.length === 0) {
        res.status(200).json(false);
    } else {
        res.status(200).json(details);
    }
});

router.post("/delete_Founder_About_data/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await Founder.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await Founder.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});

router.post(
    "/Founder_About_add_data/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await Founder.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.post(
    "/Founder_About_add",
    upload.single("file"),
    async (req, res) => {
        try {
            // ;
            const file = new Founder({
                "img_data.file_path": {
                    file_path1: req.file.path,
                    file_mimetype1: req.file.mimetype,
                    value: false,
                },
            });
            await file.save();
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            console.log(error);
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);
// About Us Chairperson

router.get("/Chairperson_About", async (req, res) => {
    const details = await Chairperson.find();
    if (details.length === 0) {
        res.status(200).json(false);
    } else {
        res.status(200).json(details);
    }
});

router.post("/delete_Chairperson_About_data/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await Chairperson.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await Chairperson.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});

router.post(
    "/Chairperson_About_add_data/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await Chairperson.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.post(
    "/Chairperson_About_add",
    upload.single("file"),
    async (req, res) => {
        try {
            // ;
            const file = new Chairperson({
                "img_data.file_path": {
                    file_path1: req.file.path,
                    file_mimetype1: req.file.mimetype,
                    value: false,
                },
            });
            await file.save();
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            console.log(error);
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);
// About Us College Profile Mission and Vision

router.get("/Mission_About", async (req, res) => {
    const details = await Mission.find();
    if (details.length === 0) {
        res.status(200).json(false);
    } else {
        res.status(200).json(details);
    }
});

router.post("/delete_Mission_About_data/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await Mission.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await Mission.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});

router.post(
    "/Mission_About_add_data/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await Mission.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.post(
    "/Mission_About_add",
    upload.single("file"),
    async (req, res) => {
        try {
            // ;
            const file = new Mission({
                "img_data.file_path": {
                    file_path1: req.file.path,
                    file_mimetype1: req.file.mimetype,
                    value: false,
                },
            });
            await file.save();
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            console.log(error);
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);
// About Us Principal

router.get("/Principal_About", async (req, res) => {
    const details = await Principal.find();
    if (details.length === 0) {
        res.status(200).json(false);
    } else {
        res.status(200).json(details);
    }
});

router.post("/delete_Principal_About_data/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await Principal.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await Principal.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});

router.post(
    "/Principal_About_add_data/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await Principal.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.post(
    "/Principal_About_add",
    upload.single("file"),
    async (req, res) => {
        try {
            // ;
            const file = new Principal({
                "img_data.file_path": {
                    file_path1: req.file.path,
                    file_mimetype1: req.file.mimetype,
                    value: false,
                },
            });
            await file.save();
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            console.log(error);
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);
// About Us VicePrincipal

router.get("/VicePrincipal_About", async (req, res) => {
    const details = await VicePrincipal.find();
    if (details.length === 0) {
        res.status(200).json(false);
    } else {
        res.status(200).json(details);
    }
});

router.post("/delete_VicePrincipal_About_data/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await VicePrincipal.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await VicePrincipal.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});

router.post(
    "/VicePrincipal_About_add_data/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await VicePrincipal.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.post(
    "/VicePrincipal_About_add",
    upload.single("file"),
    async (req, res) => {
        try {
            // ;
            const file = new VicePrincipal({
                "img_data.file_path": {
                    file_path1: req.file.path,
                    file_mimetype1: req.file.mimetype,
                    value: false,
                },
            });
            await file.save();
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            console.log(error);
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

// About Us Gallery
router.get("/About_Gallery", async (req, res) => {
    const details = await Gallery_About.find();
    res.status(200).json(details);
});

router.delete("/delete_Gallery_About/:id", async (req, res) => {
    const delete_user = await Gallery_About.findOneAndDelete({
        _id: req.params.id,
    });
    console.log(delete_user.file_path);
    await unlinkAsync(delete_user.file_path);
    res.status(200).json(delete_user + "User deleted");
});

router.post(
    "/Gallery_About_add",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            const dat = await Gallery_About.find()
            if (dat.length <= 25) {
                const file = new Gallery_About({
                    file_path: path,
                    file_mimetype: mimetype,
                });
                await file.save();
                res.send("file uploaded successfully.");
            } else {
                await unlinkAsync(path);
                res.status(402).send("Delete previous Images there is only a limit of 6 images");
            }
        } catch (error) {
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

// About Us Administration
router.post("/delete_Administration/:id", async (req, res) => {
    const delete_user = await About_Administration.findOne({ _id: req.params.id });
    const arr = delete_user.img_data.file_path;
    if (arr.length === 0) {
        await delete_user.deleteOne({ _id: req.params.id });
        // console.log(delete_user.img_data.file_path)
        res.status(200).json(delete_user + "User deleted");
    } else {
        res.status(400).json("First Delete all the images related to this section");
    }
});
router.post("/delete_img_Administration_fac/:id", async (req, res) => {
    // console.log(req.body.file_path1)
    const delete_user = await About_Administration.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.file_path": { _id: req.body.pid } } });
    await unlinkAsync(req.body.file_path1);
    res.status(200).json(delete_user + "User deleted");
});

router.post("/delete_pdf_link_Administration_fac/:id", async (req, res) => {
    const delete_user = await About_Administration.findOneAndUpdate({ _id: req.params.id }, {
        $set: {
            "img_data.pdf_path": {
                pdf_path1: "../daulatram/public/images/uploads",
                pdf_mimetype1: null,
                value: null,
            },
        },
    });
    const pdf = delete_user.img_data.pdf_path;

    if (pdf[0].pdf_mimetype1 !== "text/link") {
        console.log(pdf[0].pdf_mimetype1);
        await unlinkAsync(pdf[0].pdf_path1);
        res.status(200).json(delete_user + "User deleted");
    } else {
        console.log(pdf[0].pdf_mimetype1);
        res.status(200).json(delete_user + "User deleted");
    }
});

router.post("/delete_Administration_para/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await About_Administration.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await About_Administration.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});


router.get("/Administration", async (req, res) => {
    try {
        const files = await About_Administration.find({});
        const sortedByCreationDate = files.sort(
            (a, b) => b.createdAt - a.createdAt
        );
        res.send(sortedByCreationDate);
    } catch (error) {
        res.status(400).send("Error while getting list of files. Try again later.");
    }
});


router.post(
    "/Administration_add_para/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await About_Administration.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);


router.post(
    "/Administration_file_upload/:id",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            // console.log(path, mimetype)
            const data = await About_Administration.findOneAndUpdate({ _id: req.params.id }, {
                $set: {
                    "img_data.pdf_path": {
                        pdf_path1: path,
                        pdf_mimetype1: mimetype,
                        value: true,
                    },
                },
            });
            if (data) {
                // console.log(dat)
                res.status(200).send("file uploaded successfully.");
            } else {
                res.status(401).send("Unable to upload CV, No data found");
            }
            // console.log(dat)
        } catch (error) {
            console.log(error);
            res.status(402).send("Error while uploading file. Try again later.");
        }
    }
);
router.post("/Administration_add_link/:id", async (req, res) => {
    try {
        const { link } = req.body;

        if (!link) {
            return res
                .status(400)
                .json({ error: "Fill the Admission Details Properly" });
        }

        const data = await About_Administration.findOneAndUpdate({ _id: req.params.id }, {
            $set: {
                "img_data.pdf_path": {
                    pdf_path1: link,
                    pdf_mimetype1: "text/link",
                    value: true,
                },
            },
        });
        if (data) {
            // console.log(dat)
            res.status(200).send("file uploaded successfully.");
        } else {
            res.status(401).send("Unable to update link, No data found");
        }


    } catch (err) {
        console.log(err);
    }
});

router.post("/Administration_upload", async (req, res) => {
    try {
        // 
        const { title, description } = req.body;
        const file = new About_Administration({
            title: title,
            description: description,
            "img_data.pdf_path": { value: false },

        });
        await file.save();
        res.send("file uploaded successfully.");
    } catch (error) {
        // console.log(error)
        res.status(400).send("Error occur while uploading data");
    }
});
router.post(
    "/Administration_img_upload/:id",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            const dat = await About_Administration.findOne({ _id: req.params.id })
            const arr = dat.img_data.file_path;
            if (arr.length <= 4) {
                const data = await About_Administration.findOneAndUpdate({ _id: req.params.id }, {
                    $push: {
                        "img_data.file_path": {
                            file_path1: path,
                            file_mimetype1: mimetype,
                        },
                    },
                });
                // console.log(dat)
                if (data) {
                    res.status(200).send("file uploaded successfully.");
                }
            } else {
                await unlinkAsync(path);
                res.status(402).send("Delete previous Images there is only a limit of 6 images");
            }
        } catch (error) {
            console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.get("/Administration_download/:id", async (req, res) => {
    try {
        const file = await About_Administration.findById(req.params.id);
        res.set({
            "Content-Type": file.file_mimetype,
        });
        res.sendFile(path.join(__dirname, "..", file.file_path));
    } catch (error) {
        res.status(400).send("Error while downloading file. Try again later.");
    }
});

// Academics Facilities
router.post("/delete_Academics_Facilities_fac/:id", async (req, res) => {
    const delete_user = await Acad_Facilities.findOne({ _id: req.params.id });
    const arr = delete_user.img_data.file_path;
    if (arr.length === 0) {
        await delete_user.deleteOne({ _id: req.params.id });
        // console.log(delete_user.img_data.file_path)
        res.status(200).json(delete_user + "User deleted");
    } else {
        res.status(400).json("First Delete all the images related to this section");
    }
});
router.post("/delete_img_Academics_Facilities_fac/:id", async (req, res) => {
    // console.log(req.body.file_path1)
    const delete_user = await Acad_Facilities.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.file_path": { _id: req.body.pid } } });
    await unlinkAsync(req.body.file_path1);
    res.status(200).json(delete_user + "User deleted");
});

router.get("/Academics_Facilities", async (req, res) => {
    try {
        const files = await Acad_Facilities.find({});
        const sortedByCreationDate = files.sort(
            (a, b) => b.createdAt - a.createdAt
        );
        res.send(sortedByCreationDate);
    } catch (error) {
        res.status(400).send("Error while getting list of files. Try again later.");
    }
});

router.post("/Academics_Facilities_upload", async (req, res) => {
    try {
        // 
        const { title, description } = req.body;
        const file = new Acad_Facilities({
            title: title,
            description: description,
        });
        await file.save();
        res.send("file uploaded successfully.");
    } catch (error) {
        // console.log(error)
        res.status(400).send("Error occur while uploading data");
    }
});
router.post(
    "/Academics_Facilities_img_upload/:id",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            const dat = await Acad_Facilities.findOne({ _id: req.params.id })
            const arr = dat.img_data.file_path;
            if (arr.length <= 4) {
                const data = await Acad_Facilities.findOneAndUpdate({ _id: req.params.id }, {
                    $push: {
                        "img_data.file_path": {
                            file_path1: path,
                            file_mimetype1: mimetype,
                        },
                    },
                });
                // console.log(dat)
                if (data) {
                    res.status(200).send("file uploaded successfully.");
                }
            } else {
                await unlinkAsync(path);
                res.status(402).send("Delete previous Images there is only a limit of 6 images");
            }
        } catch (error) {
            console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.get("/Academics_Facilities_download/:id", async (req, res) => {
    try {
        const file = await Acad_Facilities.findById(req.params.id);
        res.set({
            "Content-Type": file.file_mimetype,
        });
        res.sendFile(path.join(__dirname, "..", file.file_path));
    } catch (error) {
        res.status(400).send("Error while downloading file. Try again later.");
    }
});

// Resources Centre for Innovation
router.post("/delete_Resource_centre_fac/:id", async (req, res) => {
    const delete_user = await Resources_Innovation.findOne({ _id: req.params.id });
    const arr = delete_user.img_data.file_path;
    if (arr.length === 0) {
        await delete_user.deleteOne({ _id: req.params.id });
        // console.log(delete_user.img_data.file_path)
        res.status(200).json(delete_user + "User deleted");
    } else {
        res.status(400).json("First Delete all the images related to this section");
    }
});
router.post("/delete_img_Resource_centre_fac/:id", async (req, res) => {
    // console.log(req.body.file_path1)
    const delete_user = await Resources_Innovation.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.file_path": { _id: req.body.pid } } });
    await unlinkAsync(req.body.file_path1);
    res.status(200).json(delete_user + "User deleted");
});

router.get("/Resource_centre", async (req, res) => {
    try {
        const files = await Resources_Innovation.find({});
        const sortedByCreationDate = files.sort(
            (a, b) => b.createdAt - a.createdAt
        );
        res.send(sortedByCreationDate);
    } catch (error) {
        res.status(400).send("Error while getting list of files. Try again later.");
    }
});

router.post("/Resource_centre_upload", async (req, res) => {
    try {
        // 
        const { title, description } = req.body;
        const file = new Resources_Innovation({
            title: title,
            description: description,
        });
        await file.save();
        res.send("file uploaded successfully.");
    } catch (error) {
        // console.log(error)
        res.status(400).send("Error occur while uploading data");
    }
});
router.post(
    "/Resource_center_img_upload/:id",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            const dat = await Resources_Innovation.findOne({ _id: req.params.id })
            const arr = dat.img_data.file_path;
            if (arr.length <= 4) {
                const data = await Resources_Innovation.findOneAndUpdate({ _id: req.params.id }, {
                    $push: {
                        "img_data.file_path": {
                            file_path1: path,
                            file_mimetype1: mimetype,
                        },

                    },
                });
                // console.log(dat)
                if (data) {
                    res.status(200).send("file uploaded successfully.");
                }
            } else {
                await unlinkAsync(path);
                res.status(402).send("Delete previous Images there is only a limit of 6 images");
            }
        } catch (error) {
            console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.get("/Resource_center_download/:id", async (req, res) => {
    try {
        const file = await Resources_Innovation.findById(req.params.id);
        res.set({
            "Content-Type": file.file_mimetype,
        });
        res.sendFile(path.join(__dirname, "..", file.file_path));
    } catch (error) {
        res.status(400).send("Error while downloading file. Try again later.");
    }
});

// Teacher-In Charge

router.get("/Teacher_In_Charge", async (req, res) => {
    const details = await Teacher.find();
    res.status(200).json(details);
});
router.delete("/delete_Teacher_In_Charge/:id", async (req, res) => {
    const delete_user = await Teacher.findOneAndDelete({ _id: req.params.id });
    res.status(200).json(delete_user + "User deleted");
});

router.post(
    "/Teacher_In_Charge_add",
    async (req, res) => {
        try {
            const { title, link, Tic1, Tic2 } = req.body;
            console.log(title, link, Tic1, Tic2)
            const file = new Teacher({
                title,
                link,
                Tic1,
                Tic2
            });
            await file.save();
            res.send("file uploaded successfully.");
        } catch (error) {
            console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);
// College Academics Calendar

router.get("/C_Acad_Cal", async (req, res) => {
    const details = await C_Acad_Cal.find();
    res.status(200).json(details);
});
router.delete("/delete_C_Acad_Cal/:id", async (req, res) => {
    const delete_user = await C_Acad_Cal.findOneAndDelete({ _id: req.params.id });
    await unlinkAsync(delete_user.file_path);
    res.status(200).json(delete_user + "User deleted");
});

router.post(
    "/C_Acad_Cal_add",
    upload.single("file"),
    async (req, res) => {
        try {
            const { title, link } = req.body;
            const { path, mimetype } = req.file;
            const file = new C_Acad_Cal({
                title,
                link,
                file_path: path,
                file_mimetype: mimetype,
            });
            await file.save();
            res.send("file uploaded successfully.");
        } catch (error) {
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

// University Academics Calendar

router.get("/U_Acad_Cal", async (req, res) => {
    const details = await U_Acad_Cal.find();
    res.status(200).json(details);
});
router.delete("/delete_U_Acad_Cal/:id", async (req, res) => {
    const delete_user = await U_Acad_Cal.findOneAndDelete({ _id: req.params.id });
    await unlinkAsync(delete_user.file_path);
    res.status(200).json(delete_user + "User deleted");
});

router.post(
    "/U_Acad_Cal_add",
    upload.single("file"),
    async (req, res) => {
        try {
            const { title, link } = req.body;
            const { path, mimetype } = req.file;
            const file = new U_Acad_Cal({
                title,
                link,
                file_path: path,
                file_mimetype: mimetype,
            });
            await file.save();
            res.send("file uploaded successfully.");
        } catch (error) {
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

// Academics Training

router.get("/Training_", async (req, res) => {
    const details = await Training.find();
    res.status(200).json(details);
});
router.delete("/delete_academicsTraings/:id", async (req, res) => {
    const delete_user = await Training.findOneAndDelete({ _id: req.params.id });
    await unlinkAsync(delete_user.file_path);
    res.status(200).json(delete_user + "User deleted");
});

router.post(
    "/Academics_Training_add",
    upload.single("file"),
    async (req, res) => {
        try {
            const { title, link } = req.body;
            const { path, mimetype } = req.file;
            const file = new Training({
                title,
                link,
                file_path: path,
                file_mimetype: mimetype,
            });
            await file.save();
            res.send("file uploaded successfully.");
        } catch (error) {
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

// Add on Courses
router.post("/delete_Courses/:id", async (req, res) => {
    const delete_user = await Courses.findOne({ _id: req.params.id });
    const arr = delete_user.img_data.file_path;
    if (arr.length === 0) {
        await delete_user.deleteOne({ _id: req.params.id });
        // console.log(delete_user.img_data.file_path)
        res.status(200).json(delete_user + "User deleted");
    } else {
        res.status(400).json("First Delete all the images related to this section");
    }
});
router.post("/delete_img_Courses_fac/:id", async (req, res) => {
    // console.log(req.body.file_path1)
    const delete_user = await Courses.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.file_path": { _id: req.body.pid } } });
    await unlinkAsync(req.body.file_path1);
    res.status(200).json(delete_user + "User deleted");
});

router.post("/delete_pdf_link_Courses_fac/:id", async (req, res) => {
    const delete_user = await Courses.findOneAndUpdate({ _id: req.params.id }, {
        $set: {
            "img_data.pdf_path": {
                pdf_path1: "../daulatram/public/images/uploads",
                pdf_mimetype1: null,
                value: null,
            },
        },
    });
    const pdf = delete_user.img_data.pdf_path;

    if (pdf[0].pdf_mimetype1 !== "text/link") {
        console.log(pdf[0].pdf_mimetype1);
        await unlinkAsync(pdf[0].pdf_path1);
        res.status(200).json(delete_user + "User deleted");
    } else {
        console.log(pdf[0].pdf_mimetype1);
        res.status(200).json(delete_user + "User deleted");
    }
});

router.post("/delete_Courses_para/:id", async (req, res) => {
    try {
        const { pid, type } = req.body;
        if (type === "para") {
            const delete_user = await Courses.findOneAndUpdate({ _id: req.params.id }, { $pull: { "img_data.para": { _id: pid } } });
            res.status(200).json(delete_user + "User deleted");
        } else {
            const delete_user = await Courses.findOneAndDelete({
                _id: req.params.id,
            });
            const img = delete_user.img_data.file_path;
            await unlinkAsync(img[0].file_path1);
            res.status(202).json(delete_user + "User deleted");
        }
    } catch (error) {
        console.log(error);
    }
});


router.get("/Courses", async (req, res) => {
    try {
        const files = await Courses.find({});
        const sortedByCreationDate = files.sort(
            (a, b) => b.createdAt - a.createdAt
        );
        res.send(sortedByCreationDate);
    } catch (error) {
        res.status(400).send("Error while getting list of files. Try again later.");
    }
});


router.post(
    "/Courses_add_para/:id",
    async (req, res) => {
        try {
            const { para1 } = req.body;
            await Courses.findOneAndUpdate({ _id: req.params.id }, { $push: { "img_data.para": { para1: para1 } } });
            res.status(200).send("file uploaded successfully.");
        } catch (error) {
            // console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);


router.post(
    "/Courses_file_upload/:id",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            // console.log(path, mimetype)
            const data = await Courses.findOneAndUpdate({ _id: req.params.id }, {
                $set: {
                    "img_data.pdf_path": {
                        pdf_path1: path,
                        pdf_mimetype1: mimetype,
                        value: true,
                    },
                },
            });
            if (data) {
                // console.log(dat)
                res.status(200).send("file uploaded successfully.");
            } else {
                res.status(401).send("Unable to upload CV, No data found");
            }
            // console.log(dat)
        } catch (error) {
            console.log(error);
            res.status(402).send("Error while uploading file. Try again later.");
        }
    }
);
router.post("/Courses_add_link/:id", async (req, res) => {
    try {
        const { link } = req.body;

        if (!link) {
            return res
                .status(400)
                .json({ error: "Fill the Admission Details Properly" });
        }

        const data = await Courses.findOneAndUpdate({ _id: req.params.id }, {
            $set: {
                "img_data.pdf_path": {
                    pdf_path1: link,
                    pdf_mimetype1: "text/link",
                    value: true,
                },
            },
        });
        if (data) {
            // console.log(dat)
            res.status(200).send("file uploaded successfully.");
        } else {
            res.status(401).send("Unable to update link, No data found");
        }


    } catch (err) {
        console.log(err);
    }
});

router.post("/Courses_upload", async (req, res) => {
    try {
        // 
        const { title, description } = req.body;
        const file = new Courses({
            title: title,
            description: description,
            "img_data.pdf_path": { value: false },

        });
        await file.save();
        res.send("file uploaded successfully.");
    } catch (error) {
        // console.log(error)
        res.status(400).send("Error occur while uploading data");
    }
});
router.post(
    "/Courses_img_upload/:id",
    upload.single("file"),
    async (req, res) => {
        try {
            const { path, mimetype } = req.file;
            const dat = await Courses.findOne({ _id: req.params.id })
            const arr = dat.img_data.file_path;
            if (arr.length <= 4) {
                const data = await Courses.findOneAndUpdate({ _id: req.params.id }, {
                    $push: {
                        "img_data.file_path": {
                            file_path1: path,
                            file_mimetype1: mimetype,
                        },
                    },
                });
                // console.log(dat)
                if (data) {
                    res.status(200).send("file uploaded successfully.");
                }
            } else {
                await unlinkAsync(path);
                res.status(402).send("Delete previous Images there is only a limit of 6 images");
            }
        } catch (error) {
            console.log(error)
            res.status(400).send("Error while uploading file. Try again later.");
        }
    },
    (error, req, res, next) => {
        if (error) {
            res.status(402).send(error.message);
        }
    }
);

router.get("/Courses_download/:id", async (req, res) => {
    try {
        const file = await Courses.findById(req.params.id);
        res.set({
            "Content-Type": file.file_mimetype,
        });
        res.sendFile(path.join(__dirname, "..", file.file_path));
    } catch (error) {
        res.status(400).send("Error while downloading file. Try again later.");
    }
});

module.exports = router;
