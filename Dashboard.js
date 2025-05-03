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
    if (currentUser) {
        settingsUsername.value = currentUser.username;
        settingsEmail.value = currentUser.email;
    }
    
    // Load devices
    loadDevices();
}

// Load user's devices
async function loadDevices() {
    try {
        const response = await fetch(`${API_BASE_URL}/devices`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load devices');
        }
        
        const data = await response.json();
        displayDevices(data.devices);
        populateDeviceSelector(data.devices);
    } catch (error) {
        console.error('Error loading devices:', error);
        // Handle error - maybe show a notification
    }
}

// Display devices in the devices container
function displayDevices(devices) {
    devicesContainer.innerHTML = '';
    
    if (devices.length === 0) {
        devicesContainer.innerHTML = `
            <div class="col-12 text-center">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i> You haven't added any devices yet. Add your Smart Medical Box to get started.
                </div>
            </div>
        `;
        return;
    }
    
    devices.forEach(device => {
        const deviceCard = document.createElement('div');
        deviceCard.className = 'col-md-4 mb-4';
        deviceCard.innerHTML = `
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">${device.name || 'Smart Medical Box'}</h5>
                    <h6 class="card-subtitle mb-2 text-muted">ID: ${device.device_id}</h6>
                    <p class="card-text">Added on: ${new Date(device.created_at).toLocaleDateString()}</p>
                </div>
                <div class="card-footer">
                    <button class="btn btn-sm btn-primary view-device-btn" data-device-id="${device.id}">
                        <i class="fas fa-eye"></i> View Medications
                    </button>
                    <button class="btn btn-sm btn-danger remove-device-btn" data-device-id="${device.id}">
                        <i class="fas fa-trash"></i> Remove
                    </button>
                </div>
            </div>
        `;
        devicesContainer.appendChild(deviceCard);
        
        // Add event listener to view device button
        deviceCard.querySelector('.view-device-btn').addEventListener('click', () => {
            showMedicationsSection(device.id);
        });
        
        // Add event listener to remove device button
        deviceCard.querySelector('.remove-device-btn').addEventListener('click', () => {
            removeDevice(device.id);
        });
    });
}

// Populate device selector dropdown
function populateDeviceSelector(devices) {
    deviceSelector.innerHTML = '<option value="">Select a device</option>';
    
    devices.forEach(device => {
        const option = document.createElement('option');
        option.value = device.id;
        option.textContent = device.name || `Smart Medical Box (${device.device_id})`;
        deviceSelector.appendChild(option);
    });
}

// Show medications section for a specific device
function showMedicationsSection(deviceId) {
    // Update UI
    hideAllSections();
    medicationsSection.classList.remove('d-none');
    dashboardTitle.textContent = 'Medications';
    
    // Set selected device in dropdown
    deviceSelector.value = deviceId;
    
    // Load medications for the selected device
    loadMedications(deviceId);
    
    // Update navigation
    updateNavigation('medications-nav');
}

// Load medications for a specific device
async function loadMedications(deviceId) {
    try {
        const response = await fetch(`${API_BASE_URL}/devices/${deviceId}/medications`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load medications');
        }
        
        const data = await response.json();
        displayMedications(data.medications);
    } catch (error) {
        console.error('Error loading medications:', error);
        // Handle error - maybe show a notification
    }
}

// Display medications in the table
function displayMedications(medications) {
    medicationsTableBody.innerHTML = '';
    
    if (medications.length === 0) {
        medicationsTableBody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center">No medications found</td>
            </tr>
        `;
        return;
    }
    
    medications.forEach(medication => {
        const timeStr = `${String(medication.hour).padStart(2, '0')}:${String(medication.minute).padStart(2, '0')}`;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${medication.name}</td>
            <td>${timeStr}</td>
            <td>
                <span class="badge bg-secondary">Scheduled</span>
            </td>
            <td>
                <button class="btn btn-sm btn-info view-logs-btn" data-medication-id="${medication.id}">
                    <i class="fas fa-history"></i> View Logs
                </button>
                <button class="btn btn-sm btn-danger remove-medication-btn" data-medication-id="${medication.id}">
                    <i class="fas fa-trash"></i> Remove
                </button>
            </td>
        `;
        medicationsTableBody.appendChild(row);
        
        // Add event listener to view logs button
        row.querySelector('.view-logs-btn').addEventListener('click', () => {
            loadMedicationLogs(medication.id);
        });
        
        // Add event listener to remove medication button
        row.querySelector('.remove-medication-btn').addEventListener('click', () => {
            removeMedication(medication.id);
        });
    });
}

// Load medication logs for a specific medication
async function loadMedicationLogs(medicationId) {
    try {
        const response = await fetch(`${API_BASE_URL}/medications/${medicationId}/logs`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load medication logs');
        }
        
        const data = await response.json();
        // Show logs in a modal or another section
        showMedicationLogs(data.logs);
    } catch (error) {
        console.error('Error loading medication logs:', error);
        // Handle error - maybe show a notification
    }
}

// Show medication logs
function showMedicationLogs(logs) {
    // TODO: Implement this function to display logs in a modal or another section
    console.log('Medication logs:', logs);
}

// Remove a device
async function removeDevice(deviceId) {
    if (!confirm('Are you sure you want to remove this device?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/devices/${deviceId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to remove device');
        }
        
        // Reload devices
        loadDevices();
    } catch (error) {
        console.error('Error removing device:', error);
        // Handle error - maybe show a notification
    }
}

// Remove a medication
async function removeMedication(medicationId) {
    if (!confirm('Are you sure you want to remove this medication?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/medications/${medicationId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to remove medication');
        }
        
        // Reload medications
        loadMedications(deviceSelector.value);
    } catch (error) {
        console.error('Error removing medication:', error);
        // Handle error - maybe show a notification
    }
}

// Hide all content sections
function hideAllSections() {
    devicesSection.classList.add('d-none');
    medicationsSection.classList.add('d-none');
    reportsSection.classList.add('d-none');
    settingsSection.classList.add('d-none');
}

// Update navigation active state
function updateNavigation(activeNavId) {
    // Remove active class from all nav items
    document.querySelectorAll('.nav-link').forEach(navLink => {
        navLink.classList.remove('active');
    });
    
    // Add active class to the selected nav item
    document.getElementById(activeNavId).classList.add('active');
}

// Generate charts for reports
function generateReports() {
    // Destroy existing charts if they exist
    if (adherenceChart) {
        adherenceChart.destroy();
    }
    
    if (timelineChart) {
        timelineChart.destroy();
    }
    
    // Create adherence chart
    const adherenceCtx = document.getElementById('adherence-chart').getContext('2d');
    adherenceChart = new Chart(adherenceCtx, {
        type: 'pie',
        data: {
            labels: ['Taken on Time', 'Missed', 'Taken Late'],
            datasets: [{
                data: [75, 15, 10], // Example data - replace with actual data
                backgroundColor: ['#28a745', '#dc3545', '#ffc107']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                title: {
                    display: true,
                    text: 'Medication Adherence Rate'
                }
            }
        }
    });
    
    // Create timeline chart
    const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
            datasets: [{
                label: 'Adherence Score',
                data: [100, 80, 90, 70, 85, 95, 100], // Example data - replace with actual data
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Weekly Adherence Trend'
                }
            }
        }
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Check authentication
    checkAuth();
    
    // Login form submission
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Clear previous errors
        loginError.classList.add('d-none');
        
        // Validate form
        if (!loginUsername.value || !loginPassword.value) {
            loginError.textContent = 'Please enter username and password';
            loginError.classList.remove('d-none');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: loginUsername.value,
                    password: loginPassword.value
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Login failed');
            }
            
            const data = await response.json();
            
            // Store authentication token and user info
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('currentUser', JSON.stringify(data.user));
            
            // Update global variables
            authToken = data.token;
            currentUser = data.user;
            
            // Show dashboard
            checkAuth();
            
            // Reset form
            loginForm.reset();
        } catch (error) {
            loginError.textContent = error.message;
            loginError.classList.remove('d-none');
        }
    });
    
    // Register form submission
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Clear previous messages
        registerError.classList.add('d-none');
        registerSuccess.classList.add('d-none');
        
        // Validate form
        if (!registerUsername.value || !registerEmail.value || !registerPassword.value || !registerConfirmPassword.value) {
            registerError.textContent = 'Please fill in all fields';
            registerError.classList.remove('d-none');
            return;
        }
        
        if (registerPassword.value !== registerConfirmPassword.value) {
            registerError.textContent = 'Passwords do not match';
            registerError.classList.remove('d-none');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: registerUsername.value,
                    email: registerEmail.value,
                    password: registerPassword.value
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Registration failed');
            }
            
            // Show success message
            registerSuccess.textContent = 'Registration successful! You can now login.';
            registerSuccess.classList.remove('d-none');
            
            // Reset form
            registerForm.reset();
            
            // Switch to login tab
            document.getElementById('login-tab').click();
        } catch (error) {
            registerError.textContent = error.message;
            registerError.classList.remove('d-none');
        }
    });
    
    // Navigation events
    devicesNav.addEventListener('click', (e) => {
        e.preventDefault();
        hideAllSections();
        devicesSection.classList.remove('d-none');
        dashboardTitle.textContent = 'My Devices';
        updateNavigation('devices-nav');
        loadDevices();
    });
    
    medicationsNav.addEventListener('click', (e) => {
        e.preventDefault();
        hideAllSections();
        medicationsSection.classList.remove('d-none');
        dashboardTitle.textContent = 'Medications';
        updateNavigation('medications-nav');
    });
    
    reportsNav.addEventListener('click', (e) => {
        e.preventDefault();
        hideAllSections();
        reportsSection.classList.remove('d-none');
        dashboardTitle.textContent = 'Reports';
        updateNavigation('reports-nav');
        generateReports();
    });
    
    settingsNav.addEventListener('click', (e) => {
        e.preventDefault();
        hideAllSections();
        settingsSection.classList.remove('d-none');
        dashboardTitle.textContent = 'Settings';
        updateNavigation('settings-nav');
    });
    
    logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Clear authentication data
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
        authToken = null;
        currentUser = null;
        
        // Show login screen
        checkAuth();
    });
    
    // Refresh button
    refreshBtn.addEventListener('click', () => {
        // Reload current section
        if (!devicesSection.classList.contains('d-none')) {
            loadDevices();
        } else if (!medicationsSection.classList.contains('d-none')) {
            loadMedications(deviceSelector.value);
        } else if (!reportsSection.classList.contains('d-none')) {
            generateReports();
        }
    });
    
    // Device selector change
    deviceSelector.addEventListener('change', () => {
        if (deviceSelector.value) {
            loadMedications(deviceSelector.value);
        } else {
            medicationsTableBody.innerHTML = '';
        }
    });
    
    // Add device button
    addDeviceBtn.addEventListener('click', () => {
        // Reset form and errors
        addDeviceForm.reset();
        addDeviceError.classList.add('d-none');
        
        // Show modal
        addDeviceModal.show();
    });
    
    // Add device submission
    addDeviceSubmit.addEventListener('click', async () => {
        // Clear previous errors
        addDeviceError.classList.add('d-none');
        
        // Validate form
        if (!deviceId.value) {
            addDeviceError.textContent = 'Please enter device ID';
            addDeviceError.classList.remove('d-none');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/devices`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    device_id: deviceId.value,
                    name: deviceName.value || 'My Smart Medical Box'
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to add device');
            }
            
            // Hide modal
            addDeviceModal.hide();
            
            // Reload devices
            loadDevices();
        } catch (error) {
            addDeviceError.textContent = error.message;
            addDeviceError.classList.remove('d-none');
        }
    });
    
    // Add medication button
    addMedicationBtn.addEventListener('click', () => {
        if (!deviceSelector.value) {
            alert('Please select a device first');
            return;
        }
        
        // Reset form and errors
        addMedicationForm.reset();
        addMedicationError.classList.add('d-none');
        
        // Show modal
        addMedicationModal.show();
    });
    
    // Add medication submission
    addMedicationSubmit.addEventListener('click', async () => {
        // Clear previous errors
        addMedicationError.classList.add('d-none');
        
        // Validate form
        if (!medicationName.value || !medicationTime.value) {
            addMedicationError.textContent = 'Please fill in all fields';
            addMedicationError.classList.remove('d-none');
            return;
        }
        
        // Extract hour and minute from time input
        const [hour, minute] = medicationTime.value.split(':').map(Number);
        
        try {
            const response = await fetch(`${API_BASE_URL}/devices/${deviceSelector.value}/medications`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: medicationName.value,
                    hour,
                    minute
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to add medication');
            }
            
            // Hide modal
            addMedicationModal.hide();
            
            // Reload medications
            loadMedications(deviceSelector.value);
        } catch (error) {
            addMedicationError.textContent = error.message;
            addMedicationError.classList.remove('d-none');
        }
    });
    
    // Settings form submission
    settingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Clear previous messages
        settingsError.classList.add('d-none');
        settingsSuccess.classList.add('d-none');
        
        // Validate form
        if (!settingsEmail.value) {
            settingsError.textContent = 'Email is required';
            settingsError.classList.remove('d-none');
            return;
        }
        
        // Check if passwords match if new password is provided
        if (settingsNewPassword.value && settingsNewPassword.value !== settingsConfirmPassword.value) {
            settingsError.textContent = 'Passwords do not match';
            settingsError.classList.remove('d-none');
            return;
        }
        
        // Prepare update data
        const updateData = {
            email: settingsEmail.value
        };
        
        if (settingsNewPassword.value) {
            updateData.password = settingsNewPassword.value;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/users/${currentUser.id}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updateData)
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to update settings');
            }
            
            // Update current user
            currentUser.email = settingsEmail.value;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            
            // Show success message
            settingsSuccess.textContent = 'Settings updated successfully';
            settingsSuccess.classList.remove('d-none');
            
            // Clear password fields
            settingsNewPassword.value = '';
            settingsConfirmPassword.value = '';
        } catch (error) {
            settingsError.textContent = error.message;
            settingsError.classList.remove('d-none');
        }
    });
});

// Initialize application
checkAuth();
