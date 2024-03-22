require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const multer = require("multer")
const upload = multer({ storage: "./public" })
const fs = require("fs")
const jwt = require("jsonwebtoken")

const saltRounds = 10;

app.use(cors());
app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017/CRUD")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB:", err));

const UserSchema = new mongoose.Schema({
  name: String,
  mobile: String,
  emailid: String,
  password: String,
  message: String,
});

const UserModel = mongoose.model("User", UserSchema);
const PaymentSchema = new mongoose.Schema({
  name:String,
  emailid:String,
  mobile:String,
   image: {
     data: String,
     contentType: String
 }
 });
 const PaymentModel = mongoose.model("Payment",PaymentSchema);
 
const ContactSchema = new mongoose.Schema({
  name: String,
  emailid: String,
  mobile: String,
  message: String,
});

const ContactModel = mongoose.model("Contact", ContactSchema);

// Sign-up post
app.post("/lmsusers/signup", async (req, res) => {
  try {
    console.log(req.body);
    const { name, mobile, emailid, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new UserModel({
      name,
      mobile,
      emailid,
      password: hashedPassword, 
    });

    await newUser.save();
    res.json(newUser);
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Signup get method
app.get("/lmsusers/signup", async (req, res) => {
  try {
    const users = await UserModel.find();

    if (!users || users.length === 0) {
      return res.status(401).send("No users found");
    } else {
      res.status(200).json({ message: "Users found.", users });
    }
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// function for auth header
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.status(401).json({ message: "Unauthorized" });
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Forbidden" });
    req.user = user;
    next();
  });
}

// login api with post method
app.post("/lmsusers/login", authenticateToken, async (req, res) => {
  try {
    const user = await UserModel.findOne({ emailid: req.body.emailid });
    if (!user) {
      return res.status(404).json({ message: "User does not exist" });
    }
    
    const passwordMatch = await bcrypt.compare(req.body.password, user.password);
    if (passwordMatch) {
      const accessToken = jwt.sign({ emailid: user.emailid}, process.env.ACCESS_TOKEN_SECRET);
      console.log("Access Token:", accessToken);

      res.status(200).json({ message: "Login successful", accessToken: accessToken });
    } else {
      res.status(400).json({ message: "Incorrect password" });
    }
  } catch (error) {
    console.error("Error executing query", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// get method for login
app.get("/lmsusers/login", async (req, res) => {
  try {
    const users = await UserModel.find();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error retrieving users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// image upload route
app.post("/lmsusers/paymentConfirmation", upload.single('image'), async (req, res, next) => {
  try {
      // Read the uploaded file
      const imagePath = req.file.path;
      const imageBuffer = fs.readFileSync(imagePath);

      // Convert the image buffer to a Base64 string
      const base64Image = imageBuffer.toString('base64');

      // Create a new document
      const newDocument = new PaymentModel({
          // Add the uploaded image to the image field
          name,
          emailid,
          mobile,
          image: {
              data: base64Image,
              contentType: req.file.mimetype
          }
      });

      // Save the document to MongoDB
      await newDocument.save();

      res.status(200).send("Image uploaded successfully!");
  } catch (error) {
      console.error(error);
      res.status(500).send("Error uploading image.");
  }
});

// post method for contact
app.post("/lmsusers/contact", async (req, res) => {
  try {
    const { name, emailid, mobile, message } = req.body;
    const newContact = new ContactModel({
      name,
      emailid,
      mobile,
      message
    });

    await newContact.save();

    res.json(newContact); 
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

app.listen(8000, () => {
  console.log("Server has started on port 8000");
});
