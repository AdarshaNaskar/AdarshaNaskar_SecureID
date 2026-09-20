document.addEventListener("DOMContentLoaded", () => {
  /* =====================================================
     ELEMENTS
     ===================================================== */

  const loginContainer = document.querySelector(".login-container");

  const loginForm = document.getElementById("loginForm");

  const loginIdentifier = document.getElementById("loginIdentifier");

  const loginPassword = document.getElementById("loginPassword");

  const loginButton = document.getElementById("loginButton");

  const toggleLoginPassword = document.getElementById("toggleLoginPassword");

  const loginError = document.getElementById("loginError");

  const identifierGroup = loginIdentifier?.closest(".form-group");

  const passwordGroup = loginPassword?.closest(".form-group");

  const identifierError = document.getElementById("identifierError");

  const passwordError = document.getElementById("passwordError");

  /* =====================================================
     MFA ELEMENTS
     ===================================================== */

  const mfaMethodScreen = document.getElementById("mfaMethodScreen");

  const mfaBackButton = document.getElementById("mfaBackButton");

  const mfaContinueButton = document.getElementById("mfaContinueButton");

  const mfaMethods = document.querySelectorAll(".mfa-method");

  /* =====================================================
     OTP ELEMENTS
     ===================================================== */

  const mfaOtpScreen = document.getElementById("mfaOtpScreen");

  const otpBackButton = document.getElementById("otpBackButton");

  const otpInputs = document.querySelectorAll(".otp-input");

  const otpVerifyButton = document.getElementById("otpVerifyButton");

  const otpResendButton = document.getElementById("otpResendButton");

  const otpError = document.getElementById("otpError");

  const otpTimer = document.getElementById("otpTimer");

  const otpTitle = document.getElementById("otpTitle");

  const otpDescription = document.getElementById("otpDescription");

  const otpDestination = document.getElementById("otpDestination");

  const otpIcon = document.getElementById("otpIcon");

  /* =====================================================
     AUTHENTICATOR ELEMENTS
     ===================================================== */

  const authenticatorLoginScreen = document.getElementById(
    "authenticatorLoginScreen",
  );

  const authenticatorBackButton = document.getElementById(
    "authenticatorBackButton",
  );

  const authenticatorCode = document.getElementById("authenticatorCode");

  const authenticatorVerifyButton = document.getElementById(
    "authenticatorVerifyButton",
  );

  const authenticatorError = document.getElementById("authenticatorError");

  /* =====================================================
     SUCCESS ELEMENTS
     ===================================================== */

  const loginSuccessScreen = document.getElementById("loginSuccessScreen");

  const continueToAccountButton = document.getElementById(
    "continueToAccountButton",
  );

  const logoutButton = document.getElementById("logoutButton");

  const createAccount = document.getElementById("createAccount");

  const forgotPassword = document.getElementById("forgotPassword");

  const googleLogin = document.getElementById("googleLogin");

  /* =====================================================
     LOGIN STATE
     ===================================================== */

  const state = {
    identifier: "",
    challengeId: "",
    mfaMethod: null,
    availableMethods: [],
    otpExpiresAt: null,
    otpTimerId: null,
    loading: false,
    rememberMe: false,
  };

  /* =====================================================
     GENERAL HELPERS
     ===================================================== */

  function setButtonLoading(button, loading, text) {
    if (!button) {
      return;
    }

    button.disabled = loading;

    if (loading) {
      button.dataset.originalText = button.textContent;

      button.textContent = text;
    } else if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;

      delete button.dataset.originalText;
    }
  }

  /* =====================================================
     LOGIN ERROR HELPERS
     ===================================================== */

  function clearLoginErrors() {
    identifierGroup?.classList.remove("error");

    passwordGroup?.classList.remove("error");

    if (identifierError) {
      identifierError.hidden = true;
      identifierError.textContent = "";
    }

    if (passwordError) {
      passwordError.hidden = true;
      passwordError.textContent = "";
    }

    if (loginError) {
      loginError.hidden = true;
      loginError.textContent = "";
    }
  }

  function showIdentifierError(message) {
    identifierGroup?.classList.add("error");

    if (identifierError) {
      identifierError.textContent = message;

      identifierError.hidden = false;
    }
  }

  function showPasswordError(message) {
    passwordGroup?.classList.add("error");

    if (passwordError) {
      passwordError.textContent = message;

      passwordError.hidden = false;
    }
  }

  function showLoginError(message) {
    if (loginError) {
      loginError.textContent = message;

      loginError.hidden = false;
    }
  }

  /* =====================================================
     OTP ERROR HELPERS
     ===================================================== */

  function showOtpError(message) {
    if (otpError) {
      otpError.textContent = message;
      otpError.hidden = false;
    }
  }

  function clearOtpError() {
    if (otpError) {
      otpError.hidden = true;
      otpError.textContent = "";
    }
  }

  /* =====================================================
     SCREEN MANAGEMENT
     ===================================================== */

  function hideAllScreens() {
    if (mfaMethodScreen) {
      mfaMethodScreen.hidden = true;
    }

    if (mfaOtpScreen) {
      mfaOtpScreen.hidden = true;
    }

    if (authenticatorLoginScreen) {
      authenticatorLoginScreen.hidden = true;
    }

    if (loginSuccessScreen) {
      loginSuccessScreen.hidden = true;
    }
  }

  function showLoginScreen() {
    hideAllScreens();

    if (loginContainer) {
      loginContainer.hidden = false;
    }
  }

  function showMfaMethodScreen() {
    if (loginContainer) {
      loginContainer.hidden = true;
    }

    hideAllScreens();

    if (mfaMethodScreen) {
      mfaMethodScreen.hidden = false;
    }
  }

  function showOtpScreen() {
    if (loginContainer) {
      loginContainer.hidden = true;
    }

    hideAllScreens();

    if (mfaOtpScreen) {
      mfaOtpScreen.hidden = false;
    }
  }

  function showAuthenticatorScreen() {
    if (loginContainer) {
      loginContainer.hidden = true;
    }

    hideAllScreens();

    if (authenticatorLoginScreen) {
      authenticatorLoginScreen.hidden = false;
    }

    if (authenticatorCode) {
      authenticatorCode.focus();
    }
  }

  async function showSuccessScreen() {
    if (loginContainer) {
      loginContainer.hidden = true;
    }

    hideAllScreens();

    if (loginSuccessScreen) {
      loginSuccessScreen.hidden = false;
    }

    try {
      const res = await fetch("/api/me", { credentials: "same-origin" });
      if (res.ok) {
        const data = await res.json();
        if (data?.success && data?.user) {
          state.user = data.user;
          const heading = loginSuccessScreen?.querySelector(
            ".success-heading h2",
          );
          const desc = loginSuccessScreen?.querySelector(".success-heading p");
          if (heading)
            heading.textContent = `Welcome back, ${data.user.fullName}!`;
          if (desc) desc.textContent = `Signed in as ${data.user.email}`;
        }
      }
    } catch (err) {
      console.error("Failed to load user info:", err);
    }
  }

  /* =====================================================
     PASSWORD SHOW / HIDE
     ===================================================== */

  if (loginPassword && toggleLoginPassword) {
    toggleLoginPassword.addEventListener("click", () => {
      const isHidden = loginPassword.type === "password";

      loginPassword.type = isHidden ? "text" : "password";

      toggleLoginPassword.textContent = isHidden ? "Hide" : "Show";

      toggleLoginPassword.setAttribute(
        "aria-label",
        isHidden ? "Hide password" : "Show password",
      );
    });
  }

  /* =====================================================
     REAL LOGIN REQUEST
     ===================================================== */

  if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      clearLoginErrors();

      const identifier = loginIdentifier?.value.trim() || "";

      const password = loginPassword?.value || "";

      if (!identifier) {
        showIdentifierError("Please enter your email or username.");

        loginIdentifier?.focus();

        return;
      }

      if (!password) {
        showPasswordError("Please enter your password.");

        loginPassword?.focus();

        return;
      }

      state.identifier = identifier;

      const rememberMeCheckbox = document.getElementById("rememberMe");

      state.rememberMe = rememberMeCheckbox
        ? rememberMeCheckbox.checked
        : false;

      if (state.loading) {
        return;
      }

      state.loading = true;

      setButtonLoading(loginButton, true, "Signing in...");

      try {
        const response = await fetch("/api/login", {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          credentials: "same-origin",

          body: JSON.stringify({
            email: identifier,
            password: password,
          }),
        });

        let data = null;

        try {
          data = await response.json();
        } catch {
          data = null;
        }

        if (response.status === 429) {
          showLoginError(
            data?.message || "Too many login attempts. Please try again later.",
          );

          return;
        }

        if (response.status === 401 || !response.ok) {
          showLoginError(
            data?.message || "Invalid email or password. Please try again.",
          );

          return;
        }

        if (!data || data.success !== true || !data.challengeId) {
          showLoginError("Unable to continue login. Please try again.");

          return;
        }

        state.challengeId = data.challengeId;

        state.availableMethods = Array.isArray(data.availableMethods)
          ? data.availableMethods
          : [];

        if (data.mfaRequired !== true || state.availableMethods.length === 0) {
          showLoginError(
            "No valid authentication method is configured for this account.",
          );

          return;
        }

        configureMfaMethods(state.availableMethods);

        showMfaMethodScreen();
      } catch (error) {
        console.error("Login request failed:", error);

        showLoginError("Unable to connect to the server. Please try again.");
      } finally {
        state.loading = false;

        setButtonLoading(loginButton, false);
      }
    });
  }

  /* =====================================================
     CONFIGURE MFA METHODS
     ===================================================== */

  function configureMfaMethods(availableMethods) {
    mfaMethods.forEach((method) => {
      const radio = method.querySelector('input[type="radio"]');

      if (!radio) {
        return;
      }

      const available = availableMethods.includes(radio.value);

      radio.disabled = !available;

      radio.checked = false;

      method.classList.remove("selected");

      method.classList.toggle("disabled", !available);
    });

    state.mfaMethod = null;
  }

  /* =====================================================
     MFA CARD SELECTION
     ===================================================== */

  mfaMethods.forEach((method) => {
    const radio = method.querySelector('input[type="radio"]');

    if (!radio) {
      return;
    }

    method.addEventListener("click", () => {
      if (radio.disabled) {
        return;
      }

      radio.checked = true;

      mfaMethods.forEach((item) => {
        item.classList.remove("selected");
      });

      method.classList.add("selected");
    });

    radio.addEventListener("change", () => {
      if (radio.disabled) {
        return;
      }

      mfaMethods.forEach((item) => {
        item.classList.remove("selected");
      });

      method.classList.add("selected");
    });
  });

  /* =====================================================
     MFA CONTINUE
     ===================================================== */

  if (mfaContinueButton) {
    mfaContinueButton.addEventListener("click", async () => {
      const selected = document.querySelector(
        'input[name="loginMfaMethod"]:checked',
      );

      if (!selected) {
        showLoginError("Please select an authentication method.");

        return;
      }

      if (!state.challengeId) {
        showLoginScreen();

        showLoginError("Your login session has expired. Please try again.");

        return;
      }

      if (state.loading) {
        return;
      }

      state.loading = true;

      setButtonLoading(mfaContinueButton, true, "Continuing...");

      try {
        const response = await fetch("/api/login/select-mfa", {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          credentials: "same-origin",

          body: JSON.stringify({
            challengeId: state.challengeId,

            method: selected.value,
          }),
        });

        let data = null;

        try {
          data = await response.json();
        } catch {
          data = null;
        }

        if (!response.ok || data?.success !== true) {
          showLoginError(
            data?.message ||
              "Unable to select the authentication method. Please try again.",
          );

          return;
        }

        state.mfaMethod = data.method;

        if (data.nextStep === "authenticator") {
          showAuthenticatorScreen();
        } else if (data.nextStep === "otp") {
          prepareOtpScreen(state.mfaMethod, data.expiresAt);

          showOtpScreen();
        } else {
          showLoginError("Unable to continue login. Please try again.");
        }
      } catch (error) {
        console.error("MFA selection request failed:", error);

        showLoginError("Unable to connect to the server. Please try again.");
      } finally {
        state.loading = false;

        setButtonLoading(mfaContinueButton, false);
      }
    });
  }

  /* =====================================================
     MFA BACK
     ===================================================== */

  if (mfaBackButton) {
    mfaBackButton.addEventListener("click", () => {
      mfaMethods.forEach((method) => {
        method.classList.remove("selected");
      });

      const radios = document.querySelectorAll('input[name="loginMfaMethod"]');

      radios.forEach((radio) => {
        radio.checked = false;
      });

      state.mfaMethod = null;

      showLoginScreen();
    });
  }

  /* =====================================================
     OTP SCREEN PREPARATION
     ===================================================== */

  function prepareOtpScreen(method, expiresAt) {
    clearOtp();

    clearOtpError();

    if (otpTitle) {
      otpTitle.textContent =
        method === "email" ? "Email Verification" : "SMS Verification";
    }

    if (otpDescription) {
      otpDescription.textContent = "Enter the verification code sent to";
    }

    if (otpDestination) {
      otpDestination.textContent =
        method === "email" ? "your email address" : "your mobile number";
    }

    if (otpIcon) {
      otpIcon.textContent = method === "email" ? "✉" : "💬";
    }

    startOtpDisplayTimer(expiresAt);

    if (otpResendButton) {
      otpResendButton.disabled = false;
    }

    if (otpInputs.length > 0) {
      otpInputs[0].focus();
    }
  }

  /* =====================================================
     OTP INPUT
     ===================================================== */

  otpInputs.forEach((input, index) => {
    input.addEventListener("input", () => {
      input.value = input.value.replace(/\D/g, "").slice(0, 1);

      input.classList.remove("error", "expired");

      clearOtpError();

      if (input.value && index < otpInputs.length - 1) {
        otpInputs[index + 1].focus();
      }
    });

    input.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !input.value && index > 0) {
        otpInputs[index - 1].focus();
      }

      if (event.key === "Enter") {
        event.preventDefault();
        otpVerifyButton?.click();
      }
    });

    input.addEventListener("paste", (event) => {
      event.preventDefault();

      const pasted = event.clipboardData
        .getData("text")
        .replace(/\D/g, "")
        .slice(0, otpInputs.length);

      if (!pasted) {
        return;
      }

      pasted.split("").forEach((digit, i) => {
        if (otpInputs[i]) {
          otpInputs[i].value = digit;

          otpInputs[i].classList.remove("error", "expired");
        }
      });

      clearOtpError();

      const focusIndex = Math.min(pasted.length, otpInputs.length - 1);

      otpInputs[focusIndex].focus();
    });
  });

  /* =====================================================
     GET OTP
     ===================================================== */

  function getOtp() {
    return Array.from(otpInputs)
      .map((input) => input.value)
      .join("");
  }

  /* =====================================================
     CLEAR OTP
     ===================================================== */

  function clearOtp() {
    otpInputs.forEach((input) => {
      input.value = "";

      input.classList.remove("error", "expired");
    });
  }

  /* =====================================================
     OTP TIMER
     ===================================================== */

  function startOtpDisplayTimer(expiresAt) {
    if (state.otpTimerId) {
      clearInterval(state.otpTimerId);
    }

    /*
     * Use the expiry returned by
     * the backend.
     */

    if (expiresAt && Number(expiresAt) > Date.now()) {
      state.otpExpiresAt = Number(expiresAt);
    } else {
      state.otpExpiresAt = Date.now() + 5 * 60 * 1000;
    }

    updateOtpTimer();

    state.otpTimerId = setInterval(updateOtpTimer, 1000);
  }

  function updateOtpTimer() {
    if (!otpTimer) {
      return;
    }

    const remaining = Math.max(0, state.otpExpiresAt - Date.now());

    const seconds = Math.ceil(remaining / 1000);

    const minutesText = String(Math.floor(seconds / 60)).padStart(2, "0");

    const secondsText = String(seconds % 60).padStart(2, "0");

    otpTimer.innerHTML = `Code expires in <strong>${minutesText}:${secondsText}</strong>`;

    if (remaining <= 0) {
      clearInterval(state.otpTimerId);

      state.otpTimerId = null;

      otpInputs.forEach((input) => {
        input.classList.add("expired");
      });

      showOtpError(
        "The verification code has expired. Please click Resend Code to receive a new code.",
      );
    }
  }

  /* =====================================================
     OTP BACK
     ===================================================== */

  if (otpBackButton) {
    otpBackButton.addEventListener("click", () => {
      clearOtp();

      if (state.otpTimerId) {
        clearInterval(state.otpTimerId);

        state.otpTimerId = null;
      }

      clearOtpError();

      showMfaMethodScreen();
    });
  }

  /* =====================================================
     OTP VERIFY
     ===================================================== */

  if (otpVerifyButton) {
    otpVerifyButton.addEventListener("click", async () => {
      const otp = getOtp();

      if (otp.length !== 6) {
        showOtpError("Please enter the 6-digit verification code.");

        return;
      }

      if (!state.challengeId || !state.mfaMethod) {
        showOtpError("Your login session has expired. Please log in again.");

        return;
      }

      if (state.loading) {
        return;
      }

      state.loading = true;

      setButtonLoading(otpVerifyButton, true, "Verifying...");

      try {
        console.log("Remember Me:", state.rememberMe);
        const response = await fetch("/api/verify-login-otp", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "same-origin",
          body: JSON.stringify({
            challengeId: state.challengeId,
            otp: otp,
            rememberMe: state.rememberMe === true,
          }),
        });

        let data = null;

        try {
          data = await response.json();
        } catch {
          data = null;
        }

        /* -------------------------------------------
             SUCCESS
             ------------------------------------------- */

        if (response.ok && data?.success === true) {
          if (state.otpTimerId) {
            clearInterval(state.otpTimerId);

            state.otpTimerId = null;
          }

          clearOtp();

          showSuccessScreen();

          return;
        }

        /* -------------------------------------------
             EXPIRED
             ------------------------------------------- */

        if (data?.reason === "expired") {
          otpInputs.forEach((input) => {
            input.classList.add("expired");
          });

          showOtpError(
            "The verification code has expired. Please click Resend Code to receive a new code.",
          );

          return;
        }

        /* -------------------------------------------
             LOCKED AFTER 3 ATTEMPTS
             ------------------------------------------- */

        if (data?.reason === "locked") {
          otpInputs.forEach((input) => {
            input.classList.add("error");
          });

          showOtpError(
            "You have used all 3 attempts. Please click Resend Code to receive a new OTP.",
          );

          return;
        }

        /* -------------------------------------------
             WRONG OTP
             ------------------------------------------- */

        showOtpError(
          data?.message || "Incorrect verification code. Please try again.",
        );

        otpInputs.forEach((input) => {
          input.classList.add("error");
        });
      } catch (error) {
        console.error("OTP verification failed:", error);

        showOtpError("Unable to connect to the server. Please try again.");
      } finally {
        state.loading = false;

        setButtonLoading(otpVerifyButton, false);
      }
    });
  }

  /* =====================================================
     OTP RESEND
     ===================================================== */

  if (otpResendButton) {
    otpResendButton.addEventListener("click", async () => {
      if (!state.challengeId || !state.mfaMethod) {
        showOtpError("Your login session has expired. Please log in again.");

        return;
      }

      if (!["email", "sms"].includes(state.mfaMethod)) {
        return;
      }

      if (state.loading) {
        return;
      }

      state.loading = true;

      setButtonLoading(otpResendButton, true, "Sending...");

      try {
        const response = await fetch("/api/login/resend-otp", {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          credentials: "same-origin",

          body: JSON.stringify({
            challengeId: state.challengeId,
          }),
        });

        let data = null;

        try {
          data = await response.json();
        } catch {
          data = null;
        }

        if (!response.ok || data?.success !== true) {
          showOtpError(
            data?.message ||
              "Unable to resend the verification code. Please try again.",
          );

          return;
        }

        clearOtp();

        clearOtpError();

        startOtpDisplayTimer(data.expiresAt);

        if (otpInputs.length > 0) {
          otpInputs[0].focus();
        }
      } catch (error) {
        console.error("OTP resend failed:", error);

        showOtpError("Unable to connect to the server. Please try again.");
      } finally {
        state.loading = false;

        setButtonLoading(otpResendButton, false);
      }
    });
  }

  /* =====================================================
     AUTHENTICATOR INPUT
     ===================================================== */

  if (authenticatorCode) {
    authenticatorCode.addEventListener("input", () => {
      authenticatorCode.value = authenticatorCode.value
        .replace(/\D/g, "")
        .slice(0, 6);

      authenticatorCode.classList.remove("error");

      if (authenticatorError) {
        authenticatorError.hidden = true;

        authenticatorError.textContent = "";
      }
    });

    authenticatorCode.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        authenticatorVerifyButton?.click();
      }
    });
  }

  /* =====================================================
     AUTHENTICATOR BACK
     ===================================================== */

  if (authenticatorBackButton) {
    authenticatorBackButton.addEventListener("click", () => {
      if (authenticatorCode) {
        authenticatorCode.value = "";
      }

      if (authenticatorError) {
        authenticatorError.hidden = true;

        authenticatorError.textContent = "";
      }

      showMfaMethodScreen();
    });
  }

  /* =====================================================
     AUTHENTICATOR VERIFY
     ===================================================== */

  if (authenticatorVerifyButton) {
    authenticatorVerifyButton.addEventListener("click", async () => {
      const code = authenticatorCode?.value.trim() || "";

      if (code.length !== 6) {
        if (authenticatorError) {
          authenticatorError.textContent =
            "Please enter the 6-digit verification code.";

          authenticatorError.hidden = false;
        }

        authenticatorCode?.classList.add("error");
        return;
      }

      if (!state.challengeId) {
        if (authenticatorError) {
          authenticatorError.textContent =
            "Your login session has expired. Please log in again.";

          authenticatorError.hidden = false;
        }

        return;
      }

      if (state.loading) {
        return;
      }

      state.loading = true;
      setButtonLoading(authenticatorVerifyButton, true, "Verifying...");

      try {
        const response = await fetch("/api/login/verify-authenticator", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "same-origin",
          body: JSON.stringify({
            challengeId: state.challengeId,
            code,
            rememberMe: state.rememberMe === true,
          }),
        });

        let data = null;
        try {
          data = await response.json();
        } catch {
          data = null;
        }

        if (response.ok && data?.success === true) {
          if (authenticatorCode) {
            authenticatorCode.value = "";
          }

          if (authenticatorError) {
            authenticatorError.hidden = true;
            authenticatorError.textContent = "";
          }

          showSuccessScreen();
          return;
        }

        if (authenticatorError) {
          authenticatorError.textContent =
            data?.message || "Incorrect verification code. Please try again.";
          authenticatorError.hidden = false;
        }

        authenticatorCode?.classList.add("error");
      } catch (error) {
        console.error("Authenticator verification failed:", error);

        if (authenticatorError) {
          authenticatorError.textContent =
            "Unable to connect to the server. Please try again.";
          authenticatorError.hidden = false;
        }
      } finally {
        state.loading = false;
        setButtonLoading(authenticatorVerifyButton, false);
      }
    });
  }

  /* =====================================================
     FORGOT PASSWORD
     ===================================================== */

  if (forgotPassword) {
    forgotPassword.addEventListener("click", () => {
      /*
       * Password recovery will be
       * implemented separately.
       */
    });
  }

  /* =====================================================
     GOOGLE LOGIN
     ===================================================== */

  if (googleLogin) {
    googleLogin.addEventListener("click", () => {
      /*
       * Google OAuth will be
       * implemented separately.
       */
    });
  }

  /* =====================================================
     CREATE ACCOUNT
     ===================================================== */

  if (createAccount) {
    createAccount.addEventListener("click", () => {
      window.location.href = "./index.html";
    });
  }

  /* =====================================================
     CONTINUE AFTER SUCCESS
     ===================================================== */

  /* =====================================================
   CONTINUE AFTER SUCCESS
   ===================================================== */

  if (continueToAccountButton) {
    continueToAccountButton.addEventListener("click", () => {
      const existingInfo = document.getElementById("accountInfoCard");
      if (existingInfo) {
        existingInfo.remove();
        continueToAccountButton.textContent = "View Account Details";
        return;
      }

      continueToAccountButton.textContent = "Hide Account Details";
      const card = document.createElement("div");
      card.id = "accountInfoCard";
      card.style.margin = "16px 0";
      card.style.padding = "16px";
      card.style.background = "#f0fdf4";
      card.style.border = "1px solid #bbf7d0";
      card.style.borderRadius = "8px";
      card.style.fontSize = "14px";
      card.style.color = "#166534";
      card.style.lineHeight = "1.6";
      card.style.textAlign = "left";

      const name = state.user?.fullName || "Authenticated User";
      const email = state.user?.email || state.identifier || "";

      card.innerHTML = `
        <strong>Account Details</strong><br />
        Name: ${name}<br />
        Email: ${email}<br />
        Session: <span style="color: #15803d; font-weight: 600;">Active & Protected</span><br />
        MFA: <span style="color: #15803d; font-weight: 600;">Verified</span>
      `;
      continueToAccountButton.after(card);
    });
  }

  /* =====================================================
   LOGOUT
   ===================================================== */

  if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
      if (state.loading) {
        return;
      }

      state.loading = true;

      setButtonLoading(logoutButton, true, "Logging out...");

      try {
        const response = await fetch("/api/logout", {
          method: "POST",
          credentials: "same-origin",
        });

        const data = await response.json();

        if (!response.ok || data?.success !== true) {
          alert(data?.message || "Unable to log out. Please try again.");

          return;
        }

        /*
         * Return to the login page.
         */

        window.location.href = "./login.html";
      } catch (error) {
        console.error("Logout failed:", error);

        alert("Unable to connect to the server. Please try again.");
      } finally {
        state.loading = false;

        setButtonLoading(logoutButton, false);
      }
    });
  }

  /* =====================================================
     INITIAL STATE
     ===================================================== */

  showLoginScreen();
});
