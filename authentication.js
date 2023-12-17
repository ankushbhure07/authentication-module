const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const dbPool = require('./db'); // Adjust the path to your db.js file

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Validate mobile format
function isValidMobile(mobile) {
    const mobileRegex = /^[0-9]{10}$/;
    return mobileRegex.test(mobile);
}

// Authentication route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validate inputs
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const connection = await dbPool.getConnection();

        const [userRow] = await connection.execute(
            'SELECT usr_user_id, username, first_name, last_name, password, first_login, is_logged_in FROM authentication INNER JOIN users ON users.user_id = authentication.usr_user_id WHERE username = ?',
            [username]
        );

        connection.release();

        if (userRow.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        console.log(userRow)

        const user = userRow[0];

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        // Store token in the database
        const updateTokenQuery = 'UPDATE authentication SET token = ? WHERE usr_user_id = ?';
        await dbPool.query(updateTokenQuery, [token, user.id]);

        res.status(200).json({ token, first_login: user.first_login[0], username: user.username, first_name: user.first_name, last_name: user.last_name });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, email, mobile, firstName, lastName, age, gender, profileBase64 } = req.body;

    // Validate inputs
    if (!username || !email || !mobile || !firstName || !lastName || !age || !gender || !profileBase64) {
        return res.status(400).json({ message: 'All fields are required' });
    }


    if (!isValidEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    if (!isValidMobile(mobile)) {
        return res.status(400).json({ message: 'Invalid mobile format' });
    }

    // Generate a random password
    const randomPassword = Math.random().toString(36).slice(-8); // 8-character random string

    try {
        const connection = await dbPool.getConnection();

        // Check if username or email already exists
        const [existingUser] = await connection.execute(
            'SELECT * FROM authentication INNER JOIN users ON authentication.usr_user_id = users.user_id WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUser.length > 0) {
            connection.release();
            return res.status(400).json({ message: 'Username or email already exists' });
        }

        // Hash the random password
        const hashedPassword = await bcrypt.hash(randomPassword, 10);

        // Insert user data into user table with base64 profile image
        const insertUserQuery =
            'INSERT INTO users (profile, first_name, last_name, gender, age) VALUES (?, ?, ?, ?, ?)';
        const [insertAuthResult] = await connection.query(insertUserQuery, [profileBase64, firstName, lastName, gender, age]);

        const user_id = insertAuthResult.insertId;
        console.log(user_id)
        // Insert new user into authentication table
        const insertAuthQuery =
            'INSERT INTO authentication (username, password, email, mobile, usr_user_id) VALUES (?, ?, ?, ?, ?)';
        await connection.query(insertAuthQuery, [username, hashedPassword, email, mobile, user_id]);


        connection.release();

        res.status(201).json({ message: 'Registration successful', password: randomPassword });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Change password route
app.post('/change-password', async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    // Validate inputs
    if (!username || !password || !confirmPassword) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Password and confirm password do not match' });
    }

    try {
        const connection = await dbPool.getConnection();

        // Retrieve user by username
        const [userRow] = await connection.execute('SELECT usr_user_id, password FROM authentication WHERE username = ?', [username]);
        if (userRow.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'User not found' });
        }

        const user = userRow[0];

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(password, 10);

        // Update user's password
        await connection.execute('UPDATE authentication SET password = ?, first_login = 0, is_logged_in = 1 WHERE usr_user_id = ?', [hashedNewPassword, user.usr_user_id]);

        connection.release();

        res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

//for genetrating OTP using username before visiblity of change password api
app.post('/generate-otp', async (req, res) => {
    const { username } = req.body;
    const otp = generateOTP(); // Generate OTP here
    try {
        const connection = await dbPool.getConnection();
        await connection.execute('INSERT INTO otp (username, otp_code) VALUES (?, ?)', [username, otp]);
        connection.release(); // Store OTP in the database
        const [userRow] = await connection.execute(
            'SELECT usr_user_id, username, first_name, last_name, email, first_login, is_logged_in FROM authentication INNER JOIN users ON users.user_id = authentication.usr_user_id WHERE username = ?',
            [username]
        );

        connection.release();
        // Send the OTP via email, SMS, or other preferred method
        // Return a response to indicate success
        var request = require('request');

        var html = `<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
    <div style="margin:50px auto;width:70%;padding:20px 0">
      <div style="border-bottom:1px solid #eee">
        <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">Your Brand</a>
      </div>
      <p style="font-size:1.1em">Hi, `+ userRow[0].first_name + ' ' + userRow[0].last_name + `</p>
      <p>Thank you for choosing Your Brand. Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes</p>
      <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">`+ otp + `</h2>
      <p style="font-size:0.9em;">Regards,<br />Your Brand</p>
      <hr style="border:none;border-top:1px solid #eee" />
      <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
        <p>Your Brand Inc</p>
        <p>1600 Amphitheatre Parkway</p>
        <p>California</p>
      </div>
    </div>
  </div>`;
        var options = {
            'method': 'POST',
            'url': 'https://cloudidesys.com/email-sender/send_mail.php',
            'headers': {
            },
            formData: {
                'htmlContent': html,
                'senderEmail': 'contact@cloudidesys.com',
                'receiverEmail': userRow[0].email,
                'subject': 'OTP for reset password!',
                'cc': '[]',
                'bcc': '[]'
            }
        };
        request(options, function (error, response) {
            if (error) throw new Error(error);
            console.log(response.body);
        });

        res.status(200).json({ message: 'OTP generated and sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

//verify OTP is midlware for the change password to vefy the Entered OTP with the Gnenerate OTP in generate OTP
//it will genere the key which is passed to the reset password api as payload 
app.post('/verify-otp', async (req, res) => {
    const { username, providedOTP } = req.body;
    const isValidOTP = await verifyOTP(username, providedOTP);
    if (isValidOTP) {
        // OTP is valid, you can proceed with the desired action (e.g., change password)
        res.status(200).json({ message: 'OTP is valid' });
    } else {
        // Invalid OTP
        res.status(400).json({ message: 'Invalid OTP' });
    }
});


const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000); // Generates a random 6-digit number
};


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
