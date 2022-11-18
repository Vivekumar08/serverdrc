const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const User = require("./models/adminSchema");

dotenv.config({ path: './config.env' })
require('./db/conn')
app.use(express.json());
app.use(bodyParser.urlencoded(
  { extended: true }
))

app.use(cors());
app.use(express.json());
// app.set("view engine", "ejs")


app.get("/",async(req,res)=>{
  // res.json("Server Deployed")
    const details = await User.find();
    res.status(200).json(details);
})

app.use(require('./router/api'));

const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});