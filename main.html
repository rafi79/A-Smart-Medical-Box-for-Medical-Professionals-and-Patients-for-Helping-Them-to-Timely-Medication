/**
 * Smart Medical Box Dashboard
 * Main JavaScript file to handle user interactions and API calls
 */

// API base URL
const API_BASE_URL = 'https://your-server-domain.com/api';

// Authentication token
let authToken = localStorage.getItem('authToken');
let currentUser = JSON.parse(localStorage.getItem('currentUser'));

// DOM Elements
const authSection = document.getElementById('auth-section');
const dashboardSection = document.getElementById('dashboard-section');

// Login Form
const loginForm = document.getElementById('login-form');
const loginUsername = document.getElementById('login-username');
const loginPassword = document.getElementById('login-password');
const loginError = document.getElementById('login-error');

// Register Form
const registerForm = document.getElementById('register-form');
const registerUsername = document.getElementById('register-username');
const registerEmail = document.getElementById('register-email');
const registerPassword = document.getElementById('register-password');
const registerConfirmPassword = document.getElementById('register-confirm-password');
const registerError = document.getElementById('register-error');
const registerSuccess = document.getElementById('register-success');

// Navigation
const devicesNav = document.getElementById('devices-nav');
const medicationsNav = document.getElementById('medications-nav');
const reportsNav = document.getElementById('reports-nav');
const settingsNav = document.getElementById('settings-nav');
const logoutBtn = document.getElementById('logout-btn');
const dashboardTitle = document.getElementById('dashboard-title');
const refreshBtn = document.getElementById('refresh-btn');

// Content Sections
const devicesSection = document.getElementById('devices-section');
const medicationsSection = document.getElementById('medications-section');
const reportsSection = document.getElementById('reports-section');
const settingsSection = document.getElementById('settings-section');

// Devices
const devicesContainer = document.getElementById('devices-container');
const addDeviceBtn = document.getElementById('add-device-btn');
const addDeviceModal = new bootstrap.Modal(document.getElementById('add-device-modal'));
const addDeviceForm = document.getElementById('add-device-form');
const deviceId = document.getElementById('device-id');
const deviceName = document.getElementById('device-name');
const addDeviceError = document.getElementById('add-device-error');
const addDeviceSubmit = document.getElementById('add-device-submit');

// Medications
const deviceSelector = document.getElementById('device-selector');
const medicationsTableBody = document.getElementById('medications-table-body');
const addMedicationBtn = document.getElementById('add-medication-btn');
const addMedicationModal = new bootstrap.Modal(document.getElementById('add-medication-modal'));
const addMedicationForm = document.getElementById('add-medication-form');
const medicationName = document.getElementById('medication-name');
const medicationTime = document.getElementById('medication-time');
const addMedicationError = document.getElementById('add-medication-error');
const addMedicationSubmit = document.getElementById('add-medication-submit');

// Settings
const settingsForm = document.getElementById('settings-form');
const settingsUsername = document.getElementById('settings-username');
const settingsEmail = document.getElementById('settings-email');
const settingsNewPassword = document.getElementById('settings-new-password');
const settingsConfirmPassword = document.getElementById('settings-confirm-password');
const settingsError = document.getElementById('settings-error');
const settingsSuccess = document.getElementById('settings-success');

// Charts
let adherenceChart = null;
let timelineChart = null;

// Check if user is authenticated
function checkAuth() {
    if (authToken && currentUser) {
        authSection.classList.add('d-none');
        dashboardSection.classList.remove('d-none');
        loadDashboard();
    } else {
        authSection.classList.remove('d-none');
        dashboardSection.classList.add('d-none');
    }
}

// Load dashboard data
function loadDashboard() {
    // Populate user settings
