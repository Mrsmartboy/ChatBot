// server.js

const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const crypto = require('crypto');
const nodemailer = require('nodemailer');


 
const salt=10;
app.use(cors());
app.use(express.json());
 
app.listen(8081,()=>{
    console.log("Listening...."); 
})

 // const PORT = process.env.PORT || 5000;

// Create MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'signup'
});

// Connect
/* db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('MySQL Connected');
});

app.use(bodyParser.json()); */

// signup 

function generateResetToken() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

 
// Send email with reset link
const sendResetEmail = (email, token) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'josephganjela@gmail.com', // Your email address
      pass: 'slyv qdpo zrlo zscm' // Your email password
    }
  });

  const mailOptions = {
    from: 'josephganjela@gmail.com',
    to: email,
    subject: 'Password Reset Request',
    text: `To reset your password, please click on the following link: http://localhost:3000/reset-password/${token}`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
};

// Forgot password endpoint
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  // Generate reset token
  const resetToken = generateResetToken();
  // Set token expiry time (e.g., 1 hour from now)
  const resetTokenExpiry = new Date();
  resetTokenExpiry.setHours(resetTokenExpiry.getHours() + 1);

  // Update user record in the database with reset token and expiry
  const sql = `UPDATE Users SET ResetToken = ?, ResetTokenExpiry = ? WHERE email = ?`;
  db.query(sql, [resetToken, resetTokenExpiry, email], (err, result) => {
    if (err) {
      console.error('Error updating user record: ' + err);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Send password reset email to the user
    sendResetEmail(email, resetToken);

    res.status(200).send('Password reset instructions sent to your email.');  
  });
});

// Reset password endpoint

app.post('/reset-password/:token', (req, res) => {
  const { token } = req.params; // Extract token from URL parameter
  const { newPassword } = req.body;
  const cleanedToken = token.replace(':', '');
  // Check if token and new password are provided
  if (!cleanedToken || !newPassword) {
    return res.status(400).send('Token and new password are required.');
  }

  // Check if token is valid and not expired
  const sql = `SELECT * FROM Users WHERE ResetToken = ? AND ResetTokenExpiry > NOW()`;
  db.query(sql, [cleanedToken], (err, results) => {
    if (err) {
      console.error('Error querying database: ' + err);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 0) {
      return res.status(404).send('Invalid or expired token.');
    }
    const userId = results[0].id;
    // Hash the new password
    bcrypt.hash(newPassword, 10, (hashErr, hash) => {
      if (hashErr) {
        console.error('Error hashing password: ' + hashErr);
        return res.status(500).send('Internal Server Error');
      }

      // Update user's password and clear reset token fields
      const updateSql = `UPDATE Users SET password = ?, ResetToken = NULL, ResetTokenExpiry = NULL WHERE id = ?`;
      db.query(updateSql, [hash, userId], (updateErr, updateResult) => {
        if (updateErr) {
          console.error('Error updating password: ' + updateErr);
          return res.status(500).send('Internal Server Error');
        }
        
        return res.status(200).send('Password updated successfully.');
      });
    });
  });
});


app.post('/signup',(req,res)=>{
  const sql = 'INSERT INTO users (firstName,lastName,email, password) VALUES (?)';
  const password = req.body.password
  bcrypt.hash(password.toString(),salt,(err,hash)=>{
    if (err){
      return res.status(500).json({ message: 'Error registering user' });
    }
    const values = [
      req.body.firstName,
      req.body.lastName,
      req.body.email,
      hash, 
    ]
    db.query(sql,[values],(err,data)=>{
      if (err) {
        return res.status(500).json({ message: 'Error registering user' });
      }
      res.status(201).json({ message: 'User registered successfully',data});
    })
  })  
 
  
}) 



// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  // Find user by username
  db.query('SELECT * FROM users WHERE email = ?',[email], async (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error logging in' });
    }

    if (data.length>0){
      bcrypt.compare(password.toString(),data[0].password,(err,response)=>{
        
        if (err){
          return res.json("Error")
        }
        const err_msg = "**You entered Wrong Credentials**"

        if (response){
          const id= data[0].id;
          const token = jwt.sign({id},"jwtSecretKey",{expiresIn:300});
          return res.json({Login:true,token,data}) 
        }
        return  res.json({Login:false,err_msg})
      })
    }else{
      res.json("Fail")
    }
   
  });
});


