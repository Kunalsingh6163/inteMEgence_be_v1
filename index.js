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
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer")

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
  name: String,
  emailid: String,
  mobile: String,
  files: Object,
});
const PaymentModel = mongoose.model("Payment", PaymentSchema);

const ContactSchema = new mongoose.Schema({
  name: String,
  emailid: String,
  mobile: String,
  message: String,
});

const ContactModel = mongoose.model("Contact", ContactSchema);

const ScheduleSchema = new mongoose.Schema({
  endpoint: String,
  requestData: Object,
});

const ScheduleModel = mongoose.model('Schedule', ScheduleSchema);

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
  return jwt.sign({ emailid: user.emailid }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
};

// Sign-up post
app.post("/lmsusers/signup", async (req, res) => {
  try {
    const { name, mobile, emailid, password } = req.body;

    // Check if user already exists with the provided email id
    const existingUser = await UserModel.findOne({ emailid });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "User already exists with this email id" });
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
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000, // Expires in 15mins
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
      res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: 15 * 60 * 1000, // Expires in 15mins
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
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000, // Expires in 15mins
    });
    res.status(200).json({ message: "Token refreshed", accessToken });
  } catch (error) {
    console.error("Error refreshing token", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Middleware for parsing application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// POST route for payment confirmation
app.post(
  "/lmsusers/payment-confirmation",
  upload.single("files"),
  async (req, res) => {
    // Handle the form data
    const name = req.body.name;
    const emailid = req.body.emailid;
    const mobile = req.body.mobile;
    const files = req.file; // This will contain information about the uploaded file
    const newDocument = new PaymentModel({
      // Add the uploaded image to the image field
      name,
      emailid,
      mobile,
      files,
    });

    // Save the document to MongoDB
    await newDocument.save();
    // Perform necessary operations with the received data

    // Send a response back to the client
    res.json({ status: "success", message: "Payment confirmation received" });
  }
);

// post method for contact
app.post("/lmsusers/contact", async (req, res) => {
  try {
    const { name, emailid, mobile, message } = req.body;
    const newContact = new ContactModel({
      name,
      emailid,
      mobile,
      message,
    });

    await newContact.save();

    res.json(newContact);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});
// POST for demoschedule
app.post('/lmsusers/free-demo-schedules', async (req, res) => {
  try {
    // Extract user data from the request body
    const { name, emailid, mobile } = req.body;

    // Introduce a delay of 5 seconds before processing the request
    setTimeout(async () => {
      try {
        const newRequest = new ScheduleModel({
          endpoint: '/lmsusers/free-demo-schedules',
          requestData: { name, emailid, mobile }
        });
        await newRequest.save();
        res.status(200).json({ message: "Demo session booked successfully!" });
      } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    }, 5000); // Delay of 5 seconds (5000 milliseconds)

  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


// // Route to handle POST requests for select-date-time
app.post('/lmsusers/select-date-time', async (req, res) => {
  const { dateTime } = req.body;

  try {
      const newRequest = new ScheduleModel({
          endpoint: '/lmsusers/select-date-time',
          requestData: { dateTime }
      });
      await newRequest.save();
      res.json({ message: 'Date and time saved successfully' });
  } catch (error) {
      console.error('Error while saving date and time:', error.message);
      res.status(500).json({ error: 'Failed to save date and time' });
  }
});
// app.post('/lmsusers/requests', async (req, res) => {
//   try {
//       const {name, emailid, mobile,dateTime } = req.body;
//       const newRequest = new ScheduleModel({
//           type,
//           data,
//           name, emailid, mobile,dateTime
//       });
//       await newRequest.save();
//       res.status(200).json({ message: "schedule saved successfully!" });
//   } catch (error) {
//       console.error("Error:", error);
//       res.status(500).json({ message: "Internal server error" });
//   }
// });

app.get('/lmsusers/free-demo-schedules', async (req, res) => {
  try {
    const { name, emailid, mobile } = req.body;

    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER, // Your Gmail email address
        pass: process.env.EMAIL_PASS, // Your Gmail password
      },
    });

    let mailOptions = {
      from: process.env.EMAIL_USER,
      to: 'hirok360@gmail.com',
      subject: 'New User Submission',
      text: `Name: ${name}\nEmail: ${emailid}\nMobile: ${mobile}`,
    };

    // Send email
    await transporter.sendMail(mailOptions);

    res.status(200).send('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send('Error sending email');
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
    res.status(500).send("Server Error");
  }
});

app.get("/lmsusers/payment-confirmation", async (req, res, next) => {
  try {
    const payments = await PaymentModel.find();

    if (!payments || payments.length === 0) {
      return res.status(404).send("No payment confirmations found");
    }

    // Construct an array of payment confirmation data to send back
    const paymentData = payments.map((payment) => {
      return {
        _id: payment._id,
        name: payment.name,
        emailid: payment.emailid,
        mobile: payment.mobile,
        // You might not want to include the actual file data here, just metadata
        files: payment.files,
      };
    });

    res.status(200).json(paymentData);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error retrieving payment confirmations.");
  }
});

app.listen(process.env.PORT || 8000, () => {
  console.log("Server has started");
});
