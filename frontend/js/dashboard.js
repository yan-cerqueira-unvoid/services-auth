
const API_URL = 'http://localhost/api';
const AUTH_URL = 'http://localhost/auth';

const usernameDisplay = document.getElementById('username-display');
const logoutButton = document.getElementById('logout-btn');

const protectedDataElement = document.getElementById('protected-data');
const messageElement = document.getElementById('message');

const authToken = localStorage.getItem('authToken');
if (!authToken) {
    window.location.href = '/index.html';
} else {
    loadUserInfo();
    loadProtectedData();
}

if (logoutButton) {
    logoutButton.addEventListener('click', handleLogout);
}

async function loadUserInfo() {
    try {
        const response = await fetch(`${AUTH_URL}/validate`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Falha na validação do token');
        }
        
        const userID = response.headers.get('X-User-ID');
        const username = response.headers.get('X-Username');
        const role = response.headers.get('X-User-Role');
        
        if (username) {
            usernameDisplay.textContent = `${username} (${role})`;
        } else {
            throw new Error('Informações do usuário não encontradas');
        }
        
    } catch (error) {
        console.error('Erro ao carregar informações do usuário:', error);
        showMessage(error.message, 'error');
        handleLogout();
    }
}

async function loadProtectedData() {
    try {
        const response = await fetch(`${API_URL}/data`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Falha ao carregar dados protegidos');
        }
        
        const data = await response.json();
        
        protectedDataElement.innerHTML = `
            <p><strong>ID do Usuário:</strong> ${data.userID}</p>
            <p><strong>Função:</strong> ${data.role}</p>
            <p><strong>Mensagem:</strong> ${data.data}</p>
            <p><em>Dados protegidos carregados com sucesso!</em></p>
        `;
        
    } catch (error) {
        console.error('Erro ao carregar dados protegidos:', error);
        protectedDataElement.innerHTML = `
            <p class="error">Erro: ${error.message}</p>
            <p>Não foi possível carregar os dados protegidos.</p>
        `;
    }
}

function handleLogout() {
    localStorage.removeItem('authToken');
    
    window.location.href = '/index.html';
}

function showMessage(text, type) {
    messageElement.textContent = text;
    messageElement.className = `message ${type}-message`;
    messageElement.classList.remove('hidden');
    
    setTimeout(() => {
        messageElement.classList.add('hidden');
    }, 5000);
}
