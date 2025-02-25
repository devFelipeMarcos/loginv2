const API_URL = "http://localhost:1000";

// Função de login
async function login(event) {
  event.preventDefault();
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  try {
    const response = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Erro desconhecido");
    }

    showMessage("Login bem-sucedido! Redirecionando...", false, "loginMessage");

    // Redirecionar após 1.5 segundos
    setTimeout(() => {
      window.location.href = "/dashboard.html";
    }, 1500);
  } catch (error) {
    showMessage(error.message, true, "loginMessage");
    console.error("Erro no login:", error);
  }
}

// Função de registro
async function register(event) {
  event.preventDefault();
  const username = document.getElementById("registerUser").value;
  const password = document.getElementById("registerPass").value;
  const confirmPassword = document.getElementById("confirm-password").value;

  if (password !== confirmPassword) {
    showMessage("As senhas não coincidem", true, "registerMessage");
    return;
  }

  try {
    const response = await fetch(`${API_URL}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Erro ao registrar");
    }

    showMessage("Registro bem-sucedido! Faça login.", false, "registerMessage");
    switchForms();
  } catch (error) {
    showMessage(error.message, true, "registerMessage");
    console.error("Erro no registro:", error);
  }
}

// Função para exibir mensagens
function showMessage(message, isError = true, elementId = "loginMessage") {
  const messageElement = document.getElementById(elementId);
  messageElement.textContent = message;
  messageElement.className = `message ${isError ? "error" : "success"}`;
  messageElement.style.display = "block";

  // Esconde a mensagem após 5 segundos
  setTimeout(() => {
    messageElement.style.display = "none";
  }, 5000);
}

// Função para alternar entre os formulários
function switchForms() {
  const loginForm = document.querySelector(".login-form");
  const registerForm = document.querySelector(".register-form");

  if (loginForm.style.display !== "none") {
    loginForm.style.display = "none";
    registerForm.style.display = "block";
  } else {
    loginForm.style.display = "block";
    registerForm.style.display = "none";
  }

  // Ocultar mensagens
  document.getElementById("loginMessage").style.display = "none";
  document.getElementById("registerMessage").style.display = "none";
}

// Event Listeners
document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  if (loginForm) loginForm.addEventListener("submit", login);

  const registerForm = document.getElementById("registerForm");
  if (registerForm) registerForm.addEventListener("submit", register);

  const registerLink = document.querySelector(".register-link");
  if (registerLink) {
    registerLink.addEventListener("click", function (e) {
      e.preventDefault();
      switchForms();
    });
  }

  const backToLogin = document.querySelector(".back-to-login");
  if (backToLogin) {
    backToLogin.addEventListener("click", function (e) {
      e.preventDefault();
      switchForms();
    });
  }
});
