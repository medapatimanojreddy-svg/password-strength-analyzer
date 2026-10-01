document.addEventListener("DOMContentLoaded", () => {
  const passwordInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-password");
  const meterBar = document.getElementById("meter-bar");
  const strengthBadge = document.getElementById("strength-badge");
  const feedbackMsg = document.getElementById("feedback-msg");

  // Detailed Analysis Elements (The 6 items)
  const valCommon = document.getElementById("val-common");
  const badgeCommon = document.getElementById("badge-common");

  const valScore = document.getElementById("val-score");
  const badgeScore = document.getElementById("badge-score");

  const valCase = document.getElementById("val-case");
  const badgeCase = document.getElementById("badge-case");

  const valNumbers = document.getElementById("val-numbers");
  const badgeNumbers = document.getElementById("badge-numbers");

  const valSymbols = document.getElementById("val-symbols");
  const badgeSymbols = document.getElementById("badge-symbols");

  const valWarnings = document.getElementById("val-warnings");
  const badgeWarnings = document.getElementById("badge-warnings");

  // Suggestions Card Elements
  const suggestionsCard = document.getElementById("suggestions-card");
  const suggestionsList = document.getElementById("suggestions-list");

  // Word pool for memorable passphrase suggestion
  const words = ["Falcon", "Nebula", "River", "Summit", "Cedar", "Breeze", "Echo", "Atlas", "Shadow", "Orion", "Quartz", "Solar"];
  const syms = ["!", "@", "#", "$", "%", "*", "&"];

  function generateStrongSuggestions() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*()_+";
    
    // 1. Complex 16-character password
    let complex = "";
    for (let i = 0; i < 16; i++) {
      complex += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    // 2. Memorable Passphrase
    const w1 = words[Math.floor(Math.random() * words.length)];
    const w2 = words[Math.floor(Math.random() * words.length)];
    const w3 = words[Math.floor(Math.random() * words.length)];
    const num = Math.floor(Math.random() * 89 + 10);
    const sym = syms[Math.floor(Math.random() * syms.length)];
    const passphrase = `${w1}-${w2}-${w3}${sym}${num}`;

    // 3. Compact 12-character high entropy
    let compact = "";
    for (let i = 0; i < 12; i++) {
      compact += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return [
      { pw: complex, type: "Complex Random (16 characters)" },
      { pw: passphrase, type: "Memorable Passphrase (Easy to remember)" },
      { pw: compact, type: "Compact Secure (12 characters)" }
    ];
  }

  function evaluatePassword(password) {
    if (!password) {
      return {
        score: 0,
        label: "Empty",
        color: "#94a3b8",
        feedback: "Please enter a password to evaluate its strength."
      };
    }

    const len = password.length;
    const upperCount = (password.match(/[A-Z]/g) || []).length;
    const lowerCount = (password.match(/[a-z]/g) || []).length;
    const numberCount = (password.match(/[0-9]/g) || []).length;
    const symbolCount = (password.match(/[^A-Za-z0-9]/g) || []).length;

    let varietyTypes = 0;
    if (upperCount > 0) varietyTypes++;
    if (lowerCount > 0) varietyTypes++;
    if (numberCount > 0) varietyTypes++;
    if (symbolCount > 0) varietyTypes++;

    // Calculate score (0-100)
    let score = 0;

    // Length points (up to 40)
    if (len >= 16) score += 40;
    else if (len >= 12) score += 32;
    else if (len >= 8) score += 20;
    else score += len * 2;

    // Variety points (up to 40)
    score += varietyTypes * 10;

    // Bonus for high character diversity & length
    if (len >= 10 && varietyTypes >= 3) score += 10;
    if (len >= 14 && varietyTypes === 4) score += 10;

    // Common password penalty
    const lowerPw = password.toLowerCase();
    const isCommon = typeof COMMON_PASSWORDS !== "undefined" && 
      (COMMON_PASSWORDS.has(lowerPw) || lowerPw.includes("password") || lowerPw.includes("123456") || lowerPw.includes("admin") || lowerPw.includes("qwerty"));

    if (isCommon) {
      score = Math.min(score, 25);
    }

    // Security Warnings evaluation
    const warnings = [];
    if (len < 8) {
      warnings.push("Length under 8 characters (vulnerable to brute-force)");
    }
    if (isCommon) {
      warnings.push("Matches known commonly leaked passwords");
    }
    if (/123|234|345|456|567|678|789|abc|bcd|cde|def|qwerty|asdf/i.test(lowerPw)) {
      warnings.push("Predictable sequential keyboard pattern detected");
    }
    if (/(.)\1{2,}/.test(password)) {
      warnings.push("Repeated identical characters detected (e.g. 'aaa')");
    }
    if (upperCount === 0 && lowerCount > 0) {
      warnings.push("Missing uppercase letters (A-Z)");
    }
    if (numberCount === 0) {
      warnings.push("Missing numeric digits (0-9)");
    }
    if (symbolCount === 0) {
      warnings.push("Missing special symbols (!@#$...)");
    }

    if (warnings.length >= 3) {
      score = Math.max(10, score - 15);
    }

    score = Math.max(5, Math.min(100, score));

    let label = "Very Weak";
    let color = "#dc2626";
    let feedback = "Very easy to guess. Add more character types.";

    if (score >= 85) {
      label = "Very Strong";
      color = "#0284c7";
      feedback = "Excellent! Highly secure against brute-force attacks.";
    } else if (score >= 65) {
      label = "Strong";
      color = "#059669";
      feedback = "Strong: good password complexity and length.";
    } else if (score >= 45) {
      label = "Medium";
      color = "#d97706";
      feedback = "Moderate strength: add more length or special symbols.";
    } else if (score >= 25) {
      label = "Weak";
      color = "#ea580c";
      feedback = "Weak: try adding numbers and symbols.";
    }

    return {
      score,
      label,
      color,
      feedback,
      upperCount,
      lowerCount,
      numberCount,
      symbolCount,
      isCommon,
      warnings,
      len
    };
  }

  function renderSuggestions() {
    const list = generateStrongSuggestions();
    suggestionsList.innerHTML = list.map(item => `
      <div class="suggestion-item">
        <div class="suggestion-left">
          <span class="suggestion-password">${item.pw}</span>
          <span class="suggestion-type">${item.type}</span>
        </div>
        <button type="button" class="use-password-btn" data-password="${item.pw}">
          <i class="fa-solid fa-check"></i> Use This
        </button>
      </div>
    `).join("");

    // Attach click listeners to "Use This" buttons
    const btns = suggestionsList.querySelectorAll(".use-password-btn");
    btns.forEach(btn => {
      btn.addEventListener("click", () => {
        const chosen = btn.getAttribute("data-password");
        if (chosen) {
          passwordInput.value = chosen;
          updateUI();
          window.scrollTo({ top: 0, behavior: "smooth" });
        }
      });
    });
  }

  function updateUI() {
    const password = passwordInput.value;
    const result = evaluatePassword(password);

    // 1. Hero Meter Bar & Badge
    meterBar.style.width = `${result.score}%`;
    meterBar.style.backgroundColor = result.color;

    strengthBadge.textContent = result.label;
    strengthBadge.style.color = result.color;
    strengthBadge.style.backgroundColor = `${result.color}15`;
    strengthBadge.style.border = `1px solid ${result.color}35`;

    feedbackMsg.textContent = result.feedback;

    // 2. Detailed Scroll-down Analysis
    if (!password) {
      // Empty State
      valCommon.textContent = "No password entered";
      badgeCommon.textContent = "-";
      badgeCommon.className = "analysis-badge badge-neutral";

      valScore.textContent = "0 / 100";
      badgeScore.textContent = "0 / 100";
      badgeScore.className = "analysis-badge badge-neutral";

      valCase.textContent = "None detected";
      badgeCase.textContent = "Missing";
      badgeCase.className = "analysis-badge badge-neutral";

      valNumbers.textContent = "None detected";
      badgeNumbers.textContent = "Missing";
      badgeNumbers.className = "analysis-badge badge-neutral";

      valSymbols.textContent = "None detected";
      badgeSymbols.textContent = "Missing";
      badgeSymbols.className = "analysis-badge badge-neutral";

      valWarnings.textContent = "No password entered";
      badgeWarnings.textContent = "-";
      badgeWarnings.className = "analysis-badge badge-neutral";

      // Hide suggestions when empty
      if (suggestionsCard) suggestionsCard.style.display = "none";
      return;
    }

    // 1. Check whether password is commonly used
    if (result.isCommon) {
      valCommon.textContent = "Warning: Commonly used password (high risk)";
      badgeCommon.textContent = "Commonly Used";
      badgeCommon.className = "analysis-badge badge-danger";
    } else if (result.len < 6) {
      valCommon.textContent = "Short password (vulnerable to dictionary patterns)";
      badgeCommon.textContent = "High Risk";
      badgeCommon.className = "analysis-badge badge-warning";
    } else {
      valCommon.textContent = "Safe: Not found in commonly breached lists";
      badgeCommon.textContent = "Unique & Safe";
      badgeCommon.className = "analysis-badge badge-success";
    }

    // 2. Current password score
    valScore.textContent = `${result.score} out of 100 points (${result.label})`;
    badgeScore.textContent = `${result.score} / 100`;
    if (result.score >= 80) badgeScore.className = "analysis-badge badge-success";
    else if (result.score >= 50) badgeScore.className = "analysis-badge badge-warning";
    else badgeScore.className = "analysis-badge badge-danger";

    // 3. Uppercase/lowercase
    if (result.upperCount > 0 && result.lowerCount > 0) {
      valCase.textContent = `${result.upperCount} uppercase, ${result.lowerCount} lowercase characters`;
      badgeCase.textContent = "Both Present";
      badgeCase.className = "analysis-badge badge-success";
    } else if (result.upperCount > 0 && result.lowerCount === 0) {
      valCase.textContent = `${result.upperCount} uppercase only (missing lowercase)`;
      badgeCase.textContent = "No Lowercase";
      badgeCase.className = "analysis-badge badge-warning";
    } else if (result.upperCount === 0 && result.lowerCount > 0) {
      valCase.textContent = `${result.lowerCount} lowercase only (missing uppercase)`;
      badgeCase.textContent = "No Uppercase";
      badgeCase.className = "analysis-badge badge-warning";
    } else {
      valCase.textContent = "No alphabet letters detected";
      badgeCase.textContent = "Missing";
      badgeCase.className = "analysis-badge badge-danger";
    }

    // 4. Numbers
    if (result.numberCount > 0) {
      valNumbers.textContent = `${result.numberCount} numeric digit${result.numberCount > 1 ? 's' : ''} detected`;
      badgeNumbers.textContent = "Included";
      badgeNumbers.className = "analysis-badge badge-success";
    } else {
      valNumbers.textContent = "No numbers found (digits 0-9 recommended)";
      badgeNumbers.textContent = "Missing";
      badgeNumbers.className = "analysis-badge badge-warning";
    }

    // 5. Symbols
    if (result.symbolCount > 0) {
      valSymbols.textContent = `${result.symbolCount} special character${result.symbolCount > 1 ? 's' : ''} detected`;
      badgeSymbols.textContent = "Included";
      badgeSymbols.className = "analysis-badge badge-success";
    } else {
      valSymbols.textContent = "No special symbols found (!@#$%...)";
      badgeSymbols.textContent = "Missing";
      badgeSymbols.className = "analysis-badge badge-warning";
    }

    // 6. Show security warnings
    if (result.warnings.length > 0) {
      valWarnings.textContent = result.warnings.join(" • ");
      badgeWarnings.textContent = `${result.warnings.length} Warning${result.warnings.length > 1 ? 's' : ''}`;
      badgeWarnings.className = result.warnings.length >= 2 ? "analysis-badge badge-danger" : "analysis-badge badge-warning";
    } else {
      valWarnings.textContent = "All clear: No security vulnerabilities found";
      badgeWarnings.textContent = "All Clear";
      badgeWarnings.className = "analysis-badge badge-success";
    }

    // 3. Suggestions Section: Only show if password is weak!
    const isWeak = result.label === "Very Weak" || result.label === "Weak";
    if (isWeak && password.length > 0) {
      if (suggestionsCard) {
        if (suggestionsCard.style.display === "none") {
          renderSuggestions();
        }
        suggestionsCard.style.display = "block";
      }
    } else {
      if (suggestionsCard) suggestionsCard.style.display = "none";
    }
  }

  // Event Listeners
  passwordInput.addEventListener("input", updateUI);

  // Single Eye Icon Toggle Handler
  toggleBtn.addEventListener("click", () => {
    const isPassword = passwordInput.getAttribute("type") === "password";
    passwordInput.setAttribute("type", isPassword ? "text" : "password");
    
    const icon = toggleBtn.querySelector("i");
    if (isPassword) {
      icon.className = "fa-regular fa-eye-slash";
    } else {
      icon.className = "fa-regular fa-eye";
    }
  });

  // Initial state
  updateUI();
});
