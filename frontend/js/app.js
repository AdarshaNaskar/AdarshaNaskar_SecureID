const API_BASE = "/api/registration";
const EMAIL_OTP_DURATION = 300;
const MOBILE_OTP_DURATION = 300;
const MFA_OTP_DURATION = 300;

const $ = (id) => document.getElementById(id);
const $$ = (selector) => document.querySelectorAll(selector);

const screens = {
  registration: $("registrationScreen"),
  email: $("emailVerificationScreen"),
  mobile: $("mobileVerificationScreen"),
  mfaSetup: $("mfaSetupScreen"),
  authenticator: $("authenticatorSetupScreen"),
  mfaVerification: $("mfaVerificationScreen"),
  success: $("registrationSuccessScreen"),
};

const state = {
  registrationId: null,
  email: "",
  countryCode: "",
  mobile: "",
  mfaMethod: null,
  timers: {
    email: null,
    mobile: null,
    mfa: null,
  },
  expired: {
    email: false,
    mobile: false,
    mfa: false,
  },
  busy: false,
};

document.addEventListener("DOMContentLoaded", init);

function init() {
  hideAllScreens();
  showScreen("registration");
  setProgressStep(1);

  bindPassword();
  bindMobile();
  bindRegistration();
  bindEmailOtp();
  bindMobileOtp();
  bindMfaSelection();
  bindAuthenticator();
  bindMfaVerification();
  bindNavigation();
}

function hideAllScreens() {
  Object.values(screens).forEach((screen) => {
    if (screen) screen.hidden = true;
  });
}

function showScreen(name) {
  hideAllScreens();
  if (screens[name]) screens[name].hidden = false;
}

function setProgressStep(step) {
  $$(".progress-step").forEach((element) => {
    element.classList.toggle("active", Number(element.dataset.step) === step);
  });
}

function bindPassword() {
  const password = $("password");
  const toggle = $("togglePassword");

  if (!password) return;

  password.addEventListener("input", () => {
    const value = password.value;

    updatePasswordRule("lengthRule", value.length >= 8 && value.length <= 15);
    updatePasswordRule("uppercaseRule", /[A-Z]/.test(value));
    updatePasswordRule("numberRule", /[0-9]/.test(value));
    updatePasswordRule("specialRule", /[^A-Za-z0-9]/.test(value));
  });

  if (toggle) {
    toggle.addEventListener("click", () => {
      const hidden = password.type === "password";
      password.type = hidden ? "text" : "password";
      toggle.textContent = hidden ? "Hide" : "Show";
    });
  }
}

function updatePasswordRule(id, valid) {
  const rule = $(id);
  if (!rule) return;

  const icon = rule.querySelector(".rule-icon");
  if (!icon) return;

  icon.textContent = valid ? "✓" : "○";
  rule.classList.toggle("valid", valid);
}

function bindMobile() {
  const mobile = $("mobile");
  if (!mobile) return;

  mobile.addEventListener("input", () => {
    mobile.value = mobile.value.replace(/\D/g, "").slice(0, 15);
  });
}

function bindRegistration() {
  const form = $("registrationForm");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.busy) return;

    clearRegistrationErrors();

    const payload = {
      fullName: $("fullName").value.trim(),
      email: $("email").value.trim(),
      countryCode: $("countryCode").value,
      mobile: $("mobile").value.trim(),
      password: $("password").value,
      termsAccepted: $("terms").checked,
    };

    if (!validateRegistration(payload)) return;

    state.busy = true;

    try {
      const result = await api("/start", {
        method: "POST",
        body: payload,
      });

      state.registrationId = result.registrationId;
      state.email = payload.email;
      state.countryCode = payload.countryCode;
      state.mobile = payload.mobile;

      $("verificationEmail").textContent = state.email;

      showScreen("email");
      setProgressStep(2);
      resetOtpInputs("#otpInputs");
      startTimer("email", EMAIL_OTP_DURATION, $("otpTimer"), $("resendButton"));
      focusFirst("#otpInputs");
    } catch (error) {
      showServerRegistrationError(error);
    } finally {
      state.busy = false;
    }
  });
}

function validateRegistration(data) {
  let valid = true;

  if (!data.fullName || data.fullName.length < 2) {
    showError("fullNameError", "Please enter your full name.");
    valid = false;
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    showError("emailError", "Please enter a valid email address.");
    valid = false;
  }

  if (!/^\d{7,15}$/.test(data.mobile)) {
    showError("mobileError", "Please enter a valid mobile number.");
    valid = false;
  }

  if (
    data.password.length < 8 ||
    data.password.length > 15 ||
    !/[A-Z]/.test(data.password) ||
    !/[0-9]/.test(data.password) ||
    !/[^A-Za-z0-9]/.test(data.password)
  ) {
    showError("passwordError", "Password does not meet the required criteria.");
    valid = false;
  }

  if (!data.termsAccepted) {
    showError(
      "termsError",
      "Please accept the Terms & Conditions and Privacy Policy.",
    );
    valid = false;
  }

  return valid;
}

function clearRegistrationErrors() {
  [
    "fullNameError",
    "emailError",
    "mobileError",
    "passwordError",
    "termsError",
  ].forEach((id) => clearError(id));
}

function showServerRegistrationError(error) {
  if (error.field) {
    showError(`${error.field}Error`, error.message);
  } else {
    alert(error.message || "Unable to create your account.");
  }
}

function bindEmailOtp() {
  const inputs = Array.from($$("#otpInputs input"));

  setupOtpInputs(inputs, async (otp) => {
    if (state.expired.email || state.busy) return;

    state.busy = true;

    try {
      const result = await api("/email/verify", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
          otp,
        },
      });

      clearTimer("email");

      $("verificationMobile").textContent =
        `${state.countryCode} ${maskMobile(state.mobile)}`;

      showScreen("mobile");
      setProgressStep(3);

      resetOtpInputs("#mobileOtpInputs");
      startTimer(
        "mobile",
        MOBILE_OTP_DURATION,
        $("mobileOtpTimer"),
        $("mobileResendButton"),
      );

      focusFirst("#mobileOtpInputs");
    } catch (error) {
      showOtpError("otpInputs", "otpError", error);
    } finally {
      state.busy = false;
    }
  });

  $("resendButton")?.addEventListener("click", async () => {
    if (!state.expired.email || state.busy) return;

    state.busy = true;

    try {
      const result = await api("/email/resend", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
        },
      });

      resetOtpInputs("#otpInputs");
      startTimer(
        "email",
        secondsUntil(result.expiresAt, EMAIL_OTP_DURATION),
        $("otpTimer"),
        $("resendButton"),
      );
      focusFirst("#otpInputs");
    } catch (error) {
      showOtpError("otpInputs", "otpError", error);
    } finally {
      state.busy = false;
    }
  });
}

function bindMobileOtp() {
  const inputs = Array.from($$("#mobileOtpInputs input"));

  setupOtpInputs(inputs, async (otp) => {
    if (state.expired.mobile || state.busy) return;

    state.busy = true;

    try {
      await api("/mobile/verify", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
          otp,
        },
      });

      clearTimer("mobile");
      showScreen("mfaSetup");
      setProgressStep(4);
    } catch (error) {
      showOtpError("mobileOtpInputs", "mobileOtpError", error);
    } finally {
      state.busy = false;
    }
  });

  $("mobileResendButton")?.addEventListener("click", async () => {
    if (!state.expired.mobile || state.busy) return;

    state.busy = true;

    try {
      const result = await api("/mobile/resend", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
        },
      });

      resetOtpInputs("#mobileOtpInputs");
      startTimer(
        "mobile",
        secondsUntil(result.expiresAt, MOBILE_OTP_DURATION),
        $("mobileOtpTimer"),
        $("mobileResendButton"),
      );
      focusFirst("#mobileOtpInputs");
    } catch (error) {
      showOtpError("mobileOtpInputs", "mobileOtpError", error);
    } finally {
      state.busy = false;
    }
  });

  $("changeMobileButton")?.addEventListener("click", () => {
    clearTimer("mobile");
    showScreen("registration");
    setProgressStep(1);
    $("mobile")?.focus();
  });
}

function bindMfaSelection() {
  const methods = $$(".mfa-method");
  const continueButton = $("mfaSetupContinue");

  methods.forEach((method) => {
    const radio = method.querySelector('input[name="mfaMethod"]');

    radio?.addEventListener("change", () => {
      methods.forEach((item) => item.classList.remove("selected"));
      method.classList.add("selected");
    });
  });

  continueButton?.addEventListener("click", async () => {
    const selected = document.querySelector('input[name="mfaMethod"]:checked');
    if (!selected || state.busy) return;

    state.busy = true;
    state.mfaMethod = selected.value;

    console.log("MFA SELECT DEBUG:", {
      registrationId: state.registrationId,
      mfaMethod: state.mfaMethod,
    });

    try {
      const result = await api("/mfa/select", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
          method: state.mfaMethod,
        },
      });

      if (result.nextStep === "authenticator_setup") {
        renderAuthenticatorQr(result.qrDataUrl);
        const setupKey = document.getElementById("setupKey");

        if (setupKey && result.setupKey) {
          setupKey.textContent = result.setupKey;
        }
        showScreen("authenticator");
        setProgressStep(4);
      } else {
        prepareMfaOtp(result.method);
        showScreen("mfaVerification");
        setProgressStep(4);
      }
    } catch (error) {
      alert(error.message || "Unable to configure MFA.");
    } finally {
      state.busy = false;
    }
  });
}

function renderAuthenticatorQr(dataUrl) {
  const container = $("qrCode");
  if (!container) return;

  container.innerHTML = "";

  const img = document.createElement("img");
  img.src = dataUrl;
  img.alt = "Scan this QR code with your authenticator app";
  img.width = 220;
  img.height = 220;

  container.appendChild(img);
}

// function addAuthenticatorVerificationInput() {
//   if ($("authenticatorTotpInput")) return;

//   const wrapper = document.createElement("div");
//   wrapper.id = "authenticatorTotpWrapper";
//   wrapper.className = "authenticator-totp-wrapper";

//   const label = document.createElement("label");
//   label.htmlFor = "authenticatorTotpInput";
//   label.textContent = "Enter the 6-digit code from your authenticator app";

//   const input = document.createElement("input");
//   input.id = "authenticatorTotpInput";
//   input.type = "text";
//   input.inputMode = "numeric";
//   input.maxLength = 6;
//   input.autocomplete = "one-time-code";

//   wrapper.append(label, input);

//   $("setupKey")?.after(wrapper);
// }

function bindAuthenticator() {
  $("setupKeyButton")?.addEventListener("click", () => {
    const key = $("setupKey");
    if (key) {
      key.hidden = !key.hidden;
    }
  });

  const back = () => {
    showScreen("mfaSetup");
    setProgressStep(4);
  };

  $("authenticatorBack")?.addEventListener("click", back);
  $("authenticatorBackBottom")?.addEventListener("click", back);

  $("authenticatorContinue")?.addEventListener("click", async () => {
    if (state.busy) return;

    state.busy = true;

    try {
      const result = await api("/mfa/authenticator/complete", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
        },
      });

      if (result.nextStep === "success") {
        showScreen("success");
        setProgressStep(5);
      }
    } catch (error) {
      alert(error.message || "Unable to complete authenticator setup.");
    } finally {
      state.busy = false;
    }
  });
}

function prepareMfaOtp(method) {
  const text = document.querySelector(
    "#mfaVerificationScreen .mfa-verification-content p",
  );

  if (text) {
    if (method === "sms") {
      text.innerHTML = "Enter the code sent to your<br />mobile number";
    } else {
      text.innerHTML = "Enter the code sent to your<br />email address";
    }
  }

  resetOtpInputs("#mfaOtpInputs");
  state.expired.mfa = false;
}

function bindMfaVerification() {
  const inputs = Array.from($$("#mfaOtpInputs input"));

  setupOtpInputs(inputs, async (otp) => {
    if (state.expired.mfa || state.busy) return;

    state.busy = true;

    try {
      await api("/mfa/otp/verify", {
        method: "POST",
        body: {
          registrationId: state.registrationId,
          otp,
        },
      });

      clearTimer("mfa");
      showScreen("success");
      setProgressStep(5);
    } catch (error) {
      showOtpError("mfaOtpInputs", "mfaOtpError", error);
    } finally {
      state.busy = false;
    }
  });
}

function bindNavigation() {
  $("otpBackButton")?.addEventListener("click", () => {
    clearTimer("email");
    showScreen("registration");
    setProgressStep(1);
  });

  $("mobileOtpBackButton")?.addEventListener("click", () => {
    clearTimer("mobile");
    showScreen("email");
    setProgressStep(2);
  });

  $("mfaSetupBack")?.addEventListener("click", () => {
    showScreen("mobile");
    setProgressStep(3);
  });

  $("mfaVerificationBack")?.addEventListener("click", () => {
    clearTimer("mfa");
    showScreen("mfaSetup");
    setProgressStep(4);
  });

  $("continueToLogin")?.addEventListener("click", () => {
    window.location.href = "/login.html";
  });

  $("cantAccessMfa")?.addEventListener("click", () => {
    alert("Account recovery will be implemented with the login/security flow.");
  });
}

function setupOtpInputs(inputs, onComplete) {
  inputs.forEach((input, index) => {
    input.addEventListener("input", () => {
      input.value = input.value.replace(/\D/g, "").slice(0, 1);

      const container = input.parentElement;
      container?.classList.remove("error");

      if (input.value && index < inputs.length - 1) {
        inputs[index + 1].focus();
      }

      const code = inputs.map((item) => item.value).join("");

      if (code.length === inputs.length) {
        onComplete(code);
      }
    });

    input.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !input.value && index > 0) {
        inputs[index - 1].focus();
      }

      if (event.key === "ArrowLeft" && index > 0) {
        inputs[index - 1].focus();
      }

      if (event.key === "ArrowRight" && index < inputs.length - 1) {
        inputs[index + 1].focus();
      }
    });

    input.addEventListener("paste", (event) => {
      event.preventDefault();

      const pasted = event.clipboardData
        .getData("text")
        .replace(/\D/g, "")
        .slice(0, inputs.length);

      pasted.split("").forEach((digit, i) => {
        if (inputs[i]) inputs[i].value = digit;
      });

      const last = Math.min(pasted.length, inputs.length) - 1;
      if (last >= 0) inputs[last].focus();

      if (pasted.length === inputs.length) {
        onComplete(pasted);
      }
    });
  });
}

function resetOtpInputs(selector) {
  $$(selector + " input").forEach((input) => {
    input.value = "";
    input.disabled = false;
  });

  $(selector)?.classList.remove("error");
}

function showOtpError(containerId, errorId, error) {
  const container = $(containerId);
  const message = $(errorId);

  container?.classList.add("error");

  if (!message) return;

  message.hidden = false;

  if (error.reason === "expired") {
    message.textContent = "This code has expired. Please request a new code.";
  } else if (error.reason === "locked") {
    message.textContent =
      "Maximum attempts reached. Please request a new code.";
  } else {
    message.textContent = "Incorrect code. Please try again.";
  }

  $$("#" + containerId + " input").forEach((input) => {
    input.value = "";
  });

  focusFirst("#" + containerId);
}

function startTimer(type, seconds, element, resendButton) {
  clearTimer(type);

  state.expired[type] = false;

  let remaining = Math.max(0, Math.floor(seconds));

  updateTimer(element, remaining);

  if (resendButton) {
    resendButton.disabled = true;
    resendButton.classList.remove("active");
    resendButton.textContent = "Resend code";
  }

  state.timers[type] = setInterval(() => {
    remaining -= 1;
    updateTimer(element, remaining);

    if (remaining <= 0) {
      clearTimer(type);
      state.expired[type] = true;

      if (element) element.textContent = "Expired";

      if (resendButton) {
        resendButton.disabled = false;
        resendButton.classList.add("active");
        resendButton.textContent = "Resend New Code";
      }
    }
  }, 1000);
}

function clearTimer(type) {
  if (state.timers[type]) {
    clearInterval(state.timers[type]);
    state.timers[type] = null;
  }
}

function updateTimer(element, seconds) {
  if (!element) return;

  if (seconds <= 0) {
    element.textContent = "00:00";
    return;
  }

  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;

  element.textContent = `${String(minutes).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
}

function secondsUntil(timestamp, fallback) {
  const seconds = Math.ceil((Number(timestamp) - Date.now()) / 1000);
  return seconds > 0 ? seconds : fallback;
}

function focusFirst(selector) {
  document.querySelector(`${selector} input`)?.focus();
}

function maskMobile(mobile) {
  if (mobile.length <= 4) return mobile;
  return `${"*".repeat(Math.max(0, mobile.length - 4))}${mobile.slice(-4)}`;
}

async function api(endpoint, options = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: options.method || "GET",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    credentials: "same-origin",
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    const error = new Error(
      data.message || "The request could not be completed.",
    );

    Object.assign(error, data);
    throw error;
  }

  return data;
}

function showError(id, message) {
  const element = $(id);
  if (element) element.textContent = message;
}

function clearError(id) {
  const element = $(id);
  if (element) element.textContent = "";
}
