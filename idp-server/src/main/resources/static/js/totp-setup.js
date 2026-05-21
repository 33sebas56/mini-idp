let currentChallengeToken = null;

function showMessage(message) {
    const messageBox = document.getElementById("messageBox");
    const errorBox = document.getElementById("errorBox");

    errorBox.classList.add("hidden");
    messageBox.textContent = message;
    messageBox.classList.remove("hidden");
}

function showError(message) {
    const messageBox = document.getElementById("messageBox");
    const errorBox = document.getElementById("errorBox");

    messageBox.classList.add("hidden");
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

async function postJson(url, data) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const text = await response.text();
    const body = text ? JSON.parse(text) : {};

    if (!response.ok) {
        throw new Error(body.message || body.error || "Solicitud rechazada por el servidor");
    }

    return body;
}

document.addEventListener("DOMContentLoaded", function () {
    const startForm = document.getElementById("totpStartForm");
    const confirmForm = document.getElementById("totpConfirmForm");

    startForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        try {
            showMessage("Validando credenciales...");

            const login = await postJson("/auth/login", {
                email: email,
                password: password
            });

            if (login.status === "TOTP_REQUIRED") {
                showMessage("Este usuario ya tiene TOTP configurado. Puede iniciar sesión desde Client App.");
                return;
            }

            if (login.status !== "TOTP_SETUP_REQUIRED") {
                throw new Error(login.message || "No se pudo iniciar la configuración TOTP.");
            }

            currentChallengeToken = login.challengeToken;

            const setup = await postJson("/auth/totp/setup", {
                challengeToken: currentChallengeToken
            });

            document.getElementById("qrImage").src = setup.qrCodeDataUri;
            document.getElementById("secretText").textContent = setup.secret;

            document.getElementById("setupSection").classList.remove("hidden");

            showMessage("Escanee el QR o ingrese la clave secreta manualmente en su app autenticadora.");
        } catch (error) {
            showError(error.message);
        }
    });

    confirmForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const code = document.getElementById("code").value;

        try {
            showMessage("Confirmando código TOTP...");

            await postJson("/auth/totp/confirm", {
                challengeToken: currentChallengeToken,
                code: code
            });

            document.getElementById("totpStartForm").classList.add("hidden");
            document.getElementById("setupSection").classList.add("hidden");
            document.getElementById("successSection").classList.remove("hidden");

            showMessage("Segundo factor configurado correctamente.");
        } catch (error) {
            showError(error.message);
        }
    });
});