require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer")
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

app.use(bodyParser.json());
app.use(passport.initialize());

const saltRounds = 10;

app.use(cors());
app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017/CRUD")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB:", err));

const UserSchema = new mongoose.Schema({
  googleId: {
    type: String,
    unique: true,
    required: true
  },
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
  courseName:String,
  courseId:String,
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
  demoType:String,
  userName:String,
  userEmail:String,
  userMobile:String,
  selectedDateTime:String
});

const ScheduleModel = mongoose.model('Schedule', ScheduleSchema);


// model for forgot-password
const forgotPasswordSchema = new mongoose.Schema({
  emailid:String,
  otp:String
});

const ForgotPassword = mongoose.model('ForgotPassword', forgotPasswordSchema);

const pdfUserSchema = new mongoose.Schema({
  name:String,
  emailid:String,
  mobile:String,
  courseName:String,
  
});

const pdfUser = mongoose.model('pdfUser', pdfUserSchema);




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

app.use(session({
  secret: 'hello123', // Change this to a secret key for session encryption
  resave: false,
  saveUninitialized: false
}));
// Google OAuth2 configuration
passport.use(new GoogleStrategy({
  clientID: '502417525504-r1ad88a8n7c38unlter2dfo5n189ivp5.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: '/auth/google/callback'
},
async (accessToken, refreshToken, profile, done) => {
  try {
    // Find or create user in the database based on Google profile
    let user = await UserModel.findOne({ googleId: profile.id });

    if (!user) {
      // If user does not exist, create a new user
      user = new UserModel({
        googleId: profile.id,
        emailid: profile.emails[0].value,
        name: profile.displayName
      });
      await user.save();
    }

    // Pass the user to the next middleware
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// Routes

// Google OAuth2 authentication route
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google OAuth2 callback route
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect to a page or send response
    res.redirect('/dashboard');
  }
);
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

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


// multer config
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/uploads"); // Store files in the 'public/uploads' directory
  },
  filename: function (req, file, cb) {
    cb(null, `${file.originalname}_${Date.now()}${path.extname(file.originalname)}`);
  }
});

const upload = multer({ 
  storage,
});



// POST route for payment-confirmation
app.post(
  "/lmsusers/payment-confirmation",
  upload.single("files"),
  async (req, res) => {
    try {
      // Handle the form data
      const { name, emailid, mobile,courseName,courseId } = req.body;
      const uploadedFile = req.file;

      // Move the uploaded file to the public/uploads folder
      const publicFolder = path.join(__dirname, 'public', 'uploads');
      const newFilePath = path.join(publicFolder, uploadedFile.filename);

      fs.rename(uploadedFile.path, newFilePath, async (err) => {
        if (err) {
          console.error("Error moving file:", err);
          return res.status(500).json({ error: "Failed to move file" });
        }
      
        // Construct the URL of the uploaded image dynamically using request host
        const serverURL = `${req.protocol}://${req.get('host')}`; // Get the server's URL dynamically
        const imageURL = `${serverURL}/uploads/${uploadedFile.filename}`;

        // Now you have the URL of the uploaded image, you can save it to the database
        const newDocument = new PaymentModel({
          name,
          emailid,
          mobile,
          courseName,
          courseId,
          files: imageURL, // Save the image URL to the database
        });

        // Save the document to MongoDB
        await newDocument.save();

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
          subject: 'Payment Confirmation and Course Enrollment Details',
          text: `
          Dear Admin,

          I hope this message finds you well. I am writing to confirm the successful submission of my payment for enrollment in ${courseName}. 
          Please find below the details of my transaction and enrollment for your records and further processing.

          User Information:
          - Name: ${name}
          - Email: ${emailid}
          - Mobile: ${mobile}

          Course Details:
          - Course ID: ${courseId}
          - Course Name: ${courseName}

          Payment Confirmation:
          I have successfully completed the payment process for the above-mentioned course. The payment was made on ${new Date().toDateString()}, 
          and I have attached the payment confirmation receipt along with this email for your reference.

          Uploaded Documents/Images:
          Link: ${imageURL}

          I kindly request you to confirm the receipt of my payment, the successful enrollment in ${courseName}, and the submission of all required documents. 
          If there are any additional steps I need to complete or if further information is required from my side, please let me know at your earliest convenience.

          I am looking forward to starting this learning journey and am eager to dive into the course materials. Thank you for providing this opportunity 
          and for your assistance in completing the enrollment process.

          Best regards,

          ${name}
          ${emailid}
          ${mobile}
        `
      };

    
        await transporter.sendMail(mailOptions);
    
        // Send a response back to the client
        res.json({ status: "success", message: "Payment confirmation received" });
      });
    } catch (error) {
      console.error("Error processing payment confirmation:", error);
      res.status(500).json({ error: "Internal server error" });
    }
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
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: "hirok360@gmail.com",
      subject: 'New Contact Submission Received',
      text: `
        Dear Admin,

        I hope this message finds you well. We have received a new contact submission through our website with the following details:

        - Name: ${name}
        - Email: ${emailid}
        - Mobile: ${mobile}
        - Message: ${message}

        Please find the user's contact information above for your reference. It is advisable to reach out to the user at your earliest convenience to address their needs or inquiries.

        Should you require any further information or assistance in contacting the user, please do not hesitate to get in touch with me.

        Best Regards,

        ${name}
        ${emailid}
        ${mobile}
      `
    });
    
    res.json(newContact);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});



// nodemailer transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com', // Your SMTP server hostname
  port: 587, // Your SMTP port (587 is the default for secure SMTP)
  auth: {
    user: process.env.EMAIL_USER, // Your SMTP username
    pass: process.env.EMAIL_PASS // Your SMTP password
  },
  to: process.env.To_Email
});


    // POST endpoint for initiating and verifying phone number
    // app.post("/lmsusers/verify", (req, res) => {
    //     const { verifySid, phoneNumber } = req.body;

    //     // Initiate verification +process
    //     client.verify.v2.services(verifySid)
    //       .verifications.create({ to: phoneNumber, channel: "sms" })
    //       .then((verification) => {
    //         console.log("Verification initiated:", verification.sid);
    //         res.send({ status: "Verification initiated", verificationSid: verification.sid });
    //       })
    //       .catch(error => {
    //         console.error("Error initiating verification:", error);
    //         res.status(500).send({ error: "Error initiating verification" });
    //       });
    //   });

// const admin = require('firebase-admin');

// const serviceAccount = require(".//")
// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount)
// });

// const auth = admin.auth();
// const messaging = admin.messaging();
    // POST endpoint for verifying OTP
    // app.post("/lmsusers/verify/check", (req, res) => {
    //     const { verifySid, phoneNumber, otpCode } = req.body;

    //     // Verify OTP
    //     client.verify.v2.services(verifySid)
    //       .verificationChecks.create({ to: phoneNumber, code: otpCode })
    //       .then((verification_check) => {
    //         console.log("Verification check status:", verification_check.status);
    //         res.send({ status: verification_check.status });
    //       })
    //       .catch(error => {
    //         console.error("Error verifying OTP:", error);
    //         res.status(500).send({ error: "Error verifying OTP" });
    //       });
    //   });





// // Function to generate random OTP
// app.post('/lmsusers/forgot-password', (req, res) => {
//   const { mobile } = req.body;

//   // Generate OTP
//   const otp = generateOTP();

//   // Send OTP via FCM
//   sendOTP(mobile, otp)
//     .then(() => {
//       res.status(200).json({ message: 'OTP sent successfully' });
//     })
//     .catch((error) => {
//       console.error('Error sending OTP:', error);
//       res.status(500).json({ error: 'Failed to send OTP' });
//     });
// });


// Function to send OTP via FCM
// function sendOTP(mobile, otp) {
//   const message = {
//     data: {
//       mobile: mobile,
//       otp: otp
//     },
//     token: 'DEVICE_FCM_TOKEN' // FCM token of the user's device
//   };

//   return messaging.send(message);
// }


// Function to generate OTP with expiration time
function generateOTP() {
  const otpLength = 6; 
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
  const otpExpirationTime = new Date();
  otpExpirationTime.setMinutes(otpExpirationTime.getMinutes() + 1); // Set expiration time
  return { otp, expiresAt: otpExpirationTime }; // Return OTP along with expiration time
}

// post endpoint for forgot-password
app.post('/lmsusers/forgot-password', async (req, res) => {
  const { emailid } = req.body;

  if (!emailid) {
    return res.status(400).json({ error: 'Email address is required' });
  }

  const user = await UserModel.findOne({ emailid });
  if (!user) {
    return res.status(404).json({ error: 'No user Found with this email address' });
  }
  else
  {
    const otpObj = generateOTP();

    // Create a new instance of the ForgotPassword schema
    const forgotPassword = new ForgotPassword({
      emailid: emailid,
      otp: otpObj.otp, // Access the OTP from the generated object
      expiresAt: otpObj.expiresAt 
    });

    try {
      // Save the forgotPassword instance
      await forgotPassword.save();

      // Email options
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: emailid,
        subject: 'Your Password Reset OTP',
        text: `
          Dear ${user.name},

          You've requested to reset your password. Please use the OTP below to proceed with setting up a new password:

          OTP: ${otpObj.otp}

          This OTP is valid for 10 minutes. If you did not request a password reset, please ignore this email or contact our support team for assistance.

          Best regards,
          InteMEgencePerk Support Team.
        `
      };
      // Send email
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent:', info.response);
      res.status(200).json({ message: 'OTP sent successfully' });
    } catch (error) {
      console.error('Error:', error);
      return res.status(500).json({ error: 'Failed to send OTP' });
    }
  }
});

// POST endpoint to verify OTP
app.post('/lmsusers/verify-otp', async (req, res) => {
  const {  otp } = req.body;

  if (!otp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }

  try {
    // Find the corresponding forgotPassword instance in the database
    const forgotPasswordEntry = await ForgotPassword.findOne({ otp });

    if (!forgotPasswordEntry) {
      return res.status(404).json({ error: 'Invalid OTP' });
    }

    // Check if OTP has expired
    const now = new Date();
    const expiresAt = new Date(forgotPasswordEntry.expiresAt);
    if (now > expiresAt) {
      return res.status(400).json({ error: 'OTP has expired' });
    }

    // OTP is valid, you can proceed with password reset or whatever action needed
    // For demonstration, let's just return a success message
    return res.status(200).json({ message: 'OTP verified successfully' });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Post for pdfUser
app.post("/lmsusers/pdfUser", async (req, res) => {
  try {
    const { name, emailid, mobile , courseName} = req.body;
    const newpdf = new pdfUser({
      name,
      emailid,
      mobile,
      courseName,
      
    });

    await newpdf.save();

    res.json(newpdf);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// Post for demoschedule
app.post('/lmsusers/select-date-time', async (req, res) => {
  try {
    const {demoType, userName, userEmail, userMobile, selectedDateTime } = req.body; 
    const newRequest = new ScheduleModel({
      demoType,
      userName,
      userEmail,
      userMobile,
      selectedDateTime
    });
    await newRequest.save();
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER, // Your Gmail email address
        pass: process.env.EMAIL_PASS, // Your Gmail password
      },
    });

    let mailOptions = {
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: 'Demo Scheduled Successfully',
      text: `Dear ${userName},\n\nWe're thrilled to inform you that your demo has been successfully scheduled, and we can't wait to show you what we have in store! Below are your booking details for your records:\n\n${demoType}\nName: ${userName}\nEmail: ${userEmail}\nMobile: ${userMobile}\nScheduled Date and Time: ${selectedDateTime}\n\nPlease ensure the above details are correct. Should you need to make any changes or if you have any questions ahead of your demo, do not hesitate to contact us via email or phone.\n\nWe appreciate your interest and are looking forward to demonstrating our product/service to you. Thank you for choosing us for your needs. Expect a session filled with insights and answers to all your queries.\n\nBest Regards,\n\nInteMEgencePerk Team,\n\nP.S. Please feel free to prepare any questions or specific areas you'd like us to focus on during your demo. Our aim is to make this experience as valuable as possible for you.`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).send('Email sent successfully');
  } catch (error) {
    console.error('Error sending email or saving booking details:', error);
    res.status(500).send('Error sending email or saving booking details');
  }
});






  // =====================================  PUT METHODS  =====================================

  // Route for changing password
app.put('/lmsusers/new-password', async (req, res) => {
  const { emailid, newPassword } = req.body;

  if (!emailid || !newPassword) {
    return res.status(400).json({ error: 'Email address and new password are required' });
  }

  try {
    // Check if the user exists
    const user = await UserModel.findOne({ emailid });
    if (!user) {
      return res.status(404).json({ message: "User does not exist" });
    }

    // Update the user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10); 
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: 'Failed to change password' });
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

// get api for contact
app.get("/lmsusers/contact", async (req, res) => {
  try {
    const contacts = await ContactModel.find();
    res.json(contacts);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// get for payment-confirmation
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
        courseName:payment.courseName,
        courseId:payment.courseId,
        files: payment.files,
      };
    });

    res.status(200).json(paymentData);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error retrieving payment confirmations.");
  }
});
// to show image url
app.get("/uploads/:filename", (req, res) => {
  const filename = req.params.filename;
  const imagePath = path.join(__dirname, "public", "uploads", filename);

  // Check if the file exists
  fs.access(imagePath, fs.constants.F_OK, (err) => {
    if (err) {
      // If the file doesn't exist, return a 404 error
      return res.status(404).send("File not found");
    }

    // If the file exists, send it back to the client
    res.sendFile(imagePath);
  });
});


// GET for schedules admin
app.get('/lmsusers/free-demo-schedules-admin', async (req, res) => {
  try {
    // Fetch all schedules from the database
    const schedules = await ScheduleModel.find();
    
    // If there are no schedules found, return a message
    if (!schedules || schedules.length === 0) {
      return res.status(404).json({ message: "No schedules found" });
    }

    // If schedules are found, return them in the response
    res.status(200).json(schedules);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// GET fro pdfdownload
app.get('/lmsusers/pdfUser', async (req, res) => {
  try {
    const { name, emailid, mobile, courseName } = req.query;
    
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER, // Your Gmail email address
        pass: process.env.EMAIL_PASS, // Your Gmail password
      },
    });

    let mailOptions = {
      from: process.env.EMAIL_USER,
      to: 'hirok360@gmail.com', // Change this to the recipient's email address
      subject: 'PDF User',
      text: `
        Dear Admin inteMEgencePerk,

        I hope this email finds you well. I recently downloaded the syllabus for ${courseName} from the InteMEgencePerk website,
        and wanted to reach out for some clarifications.

        Name: ${name}
        Email: ${emailid}
        Mobile: ${mobile}
        Course Name: ${courseName}

        Thank you for your attention to these matters. I look forward to your response.

        Best regards,
        ${name}
        ${emailid}
      `,
    };

    // Send email
    await transporter.sendMail(mailOptions);

    res.status(200).send('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send('Error sending email');
  }
});



app.listen(process.env.PORT || 8000, () => {
  console.log("Server has started");
});
