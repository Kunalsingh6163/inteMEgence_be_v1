require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const multer = require("multer");
const upload = multer({ dest: "./public" }); // Adjust destination directory as needed
const fs = require("fs");
const jwt = require("jsonwebtoken");


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
  refreshToken: String,
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

// Middleware to verify access token
const verifyAccessToken = (req, res, next) => {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid access token" });
  }
};


// Middleware to generate new access token from refresh token
const generateAccessToken = (user) => {
  return jwt.sign({ emailid: user.emailid }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};


// Sign-up post
app.post("/lmsusers/signup", async (req, res) => {
  try {
    const { name, mobile, emailid, password } = req.body;

    // Check if user already exists with the provided email id
    const existingUser = await UserModel.findOne({ emailid });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists with this email id" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user
    const newUser = new UserModel({
      name,
      mobile,
      emailid,
      password: hashedPassword,
    });

    // Save the new user to the database
    await newUser.save();

    // Respond with the access token
    const accessToken = generateAccessToken(newUser);
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000 // Expires in 15mins
    });
    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// login api with post method
app.post("/lmsusers/login", async (req, res) => {
  try {
    const { emailid, password } = req.body;

    // Check if the user exists
    const user = await UserModel.findOne({ emailid });
    if (!user) {
      return res.status(404).json({ message: "User does not exist" });
    }

    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
      // Respond with the existing access token
      const accessToken = generateAccessToken(user);
      res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: 15 * 60 * 1000 // Expires in 15mins
      });
      return res.status(200).json({ message: "Login successful" });
    } else {
      // Incorrect password
      return res.status(400).json({ message: "Incorrect password" });
    }
  } catch (error) {
    console.error("Error executing query", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Refresh token endpoint
app.post("/lmsusers/refresh-token", async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;

    // Verify the refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Find the user by email
    const user = await UserModel.findOne({ emailid: decoded.emailid });

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Generate a new access token
    const accessToken = generateAccessToken(user);

    // Send the new access token to the client
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000 // Expires in 15mins
    });
    res.status(200).json({ message: "Token refreshed", accessToken });
  } catch (error) {
    console.error("Error refreshing token", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// image upload route
app.post("/lmsusers/paymentConfirmation", verifyAccessToken, upload.single('image'), async (req, res, next) => {
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
// =====================================  GET METHODS  =====================================
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
// contact get api
app.get("/lmsusers/contact", async (req, res) => {
  try {
    const contacts = await ContactModel.find();
    res.json(contacts);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});
app.listen(process.env.PORT || 8000, () => {
  console.log("Server has started");
});
