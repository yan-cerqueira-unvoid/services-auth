const API_URL = 'http://localhost/api';
const AUTH_URL = 'http://localhost/auth';

const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const googleLoginButton = document.getElementById('google-login');

const showRegisterButton = document.getElementById('show-register');
const showLoginButton = document.getElementById('show-login');
const registerContainer = document.getElementById('register-container');

const loginContainer = document.querySelector('.auth-container:not(.hidden)');
const messageElement = document.getElementById('message');

const authToken = localStorage.getItem('authToken');
if (authToken) {
    window.location.href = '/dashboard.html';
}

// Event Listeners
if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
}

if (registerForm) {
    registerForm.addEventListener('submit', handleRegister);
}

if (googleLoginButton) {
    googleLoginButton.addEventListener('click', handleGoogleLogin);
}

if (showRegisterButton) {
    showRegisterButton.addEventListener('click', (e) => {
        e.preventDefault();
        loginContainer.classList.add('hidden');
        registerContainer.classList.remove('hidden');
    });
}

if (showLoginButton) {
    showLoginButton.addEventListener('click', (e) => {
        e.preventDefault();
        registerContainer.classList.add('hidden');
        loginContainer.classList.remove('hidden');
    });
}

async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${AUTH_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Falha no login');
        }
        
        localStorage.setItem('authToken', data.token);
        showMessage('Login realizado com sucesso!', 'success');
        
        setTimeout(() => {
            window.location.href = '/dashboard.html';
        }, 1000);
        
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const role = document.getElementById('role').value;
    
    try {
        const response = await fetch(`${AUTH_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password, role }),
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Falha no registro');
        }
        
        showMessage('Registro realizado com sucesso! Faça login.', 'success');
        
        registerContainer.classList.add('hidden');
        loginContainer.classList.remove('hidden');
        
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

async function handleGoogleLogin() {
    try {
        const response = await fetch(`${AUTH_URL}/oauth/google/login`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Falha ao iniciar login com Google');
        }
        
        window.location.href = data.url;
        
    } catch (error) {
        showMessage(error.message, 'error');
    }
}

function showMessage(text, type) {
    messageElement.textContent = text;
    messageElement.className = `message ${type}-message`;
    messageElement.classList.remove('hidden');
    
    setTimeout(() => {
        messageElement.classList.add('hidden');
    }, 5000);
}

