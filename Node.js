/**
 * Smart Medical Box - Server Side Implementation
 * 
 * This Node.js server handles communication with the Smart Medical Box device,
 * stores medication data in a MySQL database, and provides a web interface
 * for monitoring medication adherence.
 * 
 * Features:
 * - Secure HTTPS communication
 * - User authentication
 * - MySQL database integration
 * - RESTful API for device communication
 * - Web dashboard for monitoring
 * 
 * Created based on the paper "A Smart Medical Box for Medical Professionals
 * and Patients for Helping Them to Avail Timely Medication"
 */

const express = require('express');
const https = require('https');
const fs = require('fs');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Create Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// User login
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Check if user exists
    db.query('SELECT * FROM users WHERE username = ?', 
      [username], 
      async (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = results[0];
        
        // Check password
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
          { id: user.id, username: user.username },
          JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        // Login successful
        res.status(200).json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email
          }
        });
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Register a new device
app.post('/api/devices', authenticateJWT, (req, res) => {
  try {
    const { device_id, name } = req.body;
    const user_id = req.user.id;
    
    // Validate input
    if (!device_id) {
      return res.status(400).json({ error: 'Device ID is required' });
    }
    
    // Check if device already exists
    db.query('SELECT * FROM devices WHERE device_id = ?', 
      [device_id], 
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length > 0) {
          return res.status(409).json({ error: 'Device already registered' });
        }
        
        // Insert device into database
        db.query('INSERT INTO devices (device_id, user_id, name) VALUES (?, ?, ?)',
          [device_id, user_id, name || 'My Smart Medical Box'],
          (err, result) => {
            if (err) {
              console.error('Error registering device:', err);
              return res.status(500).json({ error: 'Error registering device' });
            }
            
            // Device registered successfully
            res.status(201).json({ 
              message: 'Device registered successfully',
              device_id: result.insertId
            });
          }
        );
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint for receiving medication data from device
app.post('/api/medications', authenticateDevice, (req, res) => {
  try {
    const { medication, hour, minute, taken } = req.body;
    const device_id = req.device.id;
    
    // Validate input
    if (!medication || hour === undefined || minute === undefined) {
      return res.status(400).json({ error: 'Medication details required' });
    }
    
    // Get device database ID
    db.query('SELECT id FROM devices WHERE device_id = ?', 
      [device_id], 
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'Device not found' });
        }
        
        const deviceDbId = results[0].id;
        
        // Check if medication already exists
        db.query('SELECT id FROM medications WHERE device_id = ? AND name = ? AND hour = ? AND minute = ?',
          [deviceDbId, medication, hour, minute],
          (err, results) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Database error' });
            }
            
            let medicationId;
            
            if (results.length === 0) {
              // Insert new medication
              db.query('INSERT INTO medications (device_id, name, hour, minute) VALUES (?, ?, ?, ?)',
                [deviceDbId, medication, hour, minute],
                (err, result) => {
                  if (err) {
                    console.error('Error adding medication:', err);
                    return res.status(500).json({ error: 'Error adding medication' });
                  }
                  
                  medicationId = result.insertId;
                  
                  // If taken flag is true, log it
                  if (taken) {
                    logMedicationTaken(medicationId, res);
                  } else {
                    // Medication added successfully
                    res.status(201).json({ 
                      message: 'Medication added successfully',
                      medication_id: medicationId
                    });
                  }
                }
              );
            } else {
              medicationId = results[0].id;
              
              // If taken flag is true, log it
              if (taken) {
                logMedicationTaken(medicationId, res);
              } else {
                // Medication already exists
                res.status(200).json({ 
                  message: 'Medication already exists',
                  medication_id: medicationId
                });
              }
            }
          }
        );
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Function to log medication as taken
function logMedicationTaken(medicationId, res) {
  db.query('INSERT INTO medication_logs (medication_id, taken, taken_at) VALUES (?, true, NOW())',
    [medicationId],
    (err, result) => {
      if (err) {
        console.error('Error logging medication:', err);
        return res.status(500).json({ error: 'Error logging medication' });
      }
      
      // Medication logged successfully
      res.status(200).json({ 
        message: 'Medication logged successfully',
        log_id: result.insertId
      });
    }
  );
}

// Get user's devices
app.get('/api/devices', authenticateJWT, (req, res) => {
  try {
    const user_id = req.user.id;
    
    db.query('SELECT * FROM devices WHERE user_id = ?', 
      [user_id], 
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        res.status(200).json({ devices: results });
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get device medications
app.get('/api/devices/:deviceId/medications', authenticateJWT, (req, res) => {
  try {
    const { deviceId } = req.params;
    const user_id = req.user.id;
    
    // Verify device belongs to user
    db.query('SELECT id FROM devices WHERE id = ? AND user_id = ?', 
      [deviceId, user_id], 
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'Device not found or not authorized' });
        }
        
        // Get medications
        db.query('SELECT * FROM medications WHERE device_id = ?', 
          [deviceId], 
          (err, results) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Database error' });
            }
            
            res.status(200).json({ medications: results });
          }
        );
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get medication logs
app.get('/api/medications/:medicationId/logs', authenticateJWT, (req, res) => {
  try {
    const { medicationId } = req.params;
    const user_id = req.user.id;
    
    // Verify medication belongs to user
    db.query(`
      SELECT ml.* 
      FROM medication_logs ml
      JOIN medications m ON ml.medication_id = m.id
      JOIN devices d ON m.device_id = d.id
      WHERE m.id = ? AND d.user_id = ?
      ORDER BY ml.taken_at DESC
    `, 
      [medicationId, user_id], 
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        res.status(200).json({ logs: results });
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve static dashboard files
app.use(express.static('public'));

// SSL certificate and key
const sslOptions = {
  key: fs.readFileSync('path/to/private.key'),
  cert: fs.readFileSync('path/to/certificate.crt')
};

// Start HTTPS server
const PORT = process.env.PORT || 443;
https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.use('/api/', limiter);

// Body parser middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'smart_med_user',
  password: 'your_secure_password',
  database: 'smart_medical_box'
});

// Connect to database
db.connect(err => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Connected to MySQL database');
  
  // Initialize database tables if they don't exist
  initializeDatabase();
});

// Initialize database tables
function initializeDatabase() {
  // Users table
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      email VARCHAR(100) NOT NULL UNIQUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  
  // Devices table
  const createDevicesTable = `
    CREATE TABLE IF NOT EXISTS devices (
      id INT AUTO_INCREMENT PRIMARY KEY,
      device_id VARCHAR(50) NOT NULL UNIQUE,
      user_id INT,
      name VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `;
  
  // Medications table
  const createMedicationsTable = `
    CREATE TABLE IF NOT EXISTS medications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      device_id INT,
      name VARCHAR(100) NOT NULL,
      hour TINYINT NOT NULL,
      minute TINYINT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id)
    )
  `;
  
  // Medication logs table
  const createMedicationLogsTable = `
    CREATE TABLE IF NOT EXISTS medication_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      medication_id INT,
      taken BOOLEAN DEFAULT FALSE,
      taken_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (medication_id) REFERENCES medications(id)
    )
  `;
  
  // Execute queries
  db.query(createUsersTable, err => {
    if (err) console.error('Error creating users table:', err);
    else console.log('Users table ready');
  });
  
  db.query(createDevicesTable, err => {
    if (err) console.error('Error creating devices table:', err);
    else console.log('Devices table ready');
  });
  
  db.query(createMedicationsTable, err => {
    if (err) console.error('Error creating medications table:', err);
    else console.log('Medications table ready');
  });
  
  db.query(createMedicationLogsTable, err => {
    if (err) console.error('Error creating medication logs table:', err);
    else console.log('Medication logs table ready');
  });
}

// JWT secret
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// Authentication middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}

// Device authentication middleware
function authenticateDevice(req, res, next) {
  const deviceId = req.headers['x-device-id'];
  const deviceSecret = req.headers['x-device-secret'];
  
  if (!deviceId || !deviceSecret) {
    return res.status(401).json({ error: 'Device credentials required' });
  }
  
  // In a real implementation, you'd validate these credentials against the database
  // For this demo, we'll assume the device is authenticated
  req.device = { id: deviceId };
  next();
}

// Encryption functions
function encrypt(text) {
  const algorithm = 'aes-256-cbc';
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}

function decrypt(encryptedData, iv) {
  const algorithm = 'aes-256-cbc';
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
  const decipher = crypto.createDecipheriv(
    algorithm, 
    key, 
    Buffer.from(iv, 'hex')
  );
  
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    // Validate input
    if (!username || !password || !email) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user already exists
    db.query('SELECT * FROM users WHERE username = ? OR email = ?', 
      [username, email], 
      async (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length > 0) {
          return res.status(409).json({ error: 'Username or email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert user into database
        db.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
          [username, hashedPassword, email],
          (err, result) => {
            if (err) {
              console.error('Error registering user:', err);
              return res.status(500).json({ error: 'Error registering user' });
            }
            
            // User registered successfully
            res.status(201).json({ message: 'User registered successfully' });
          }
        );
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
