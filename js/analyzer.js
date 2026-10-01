/**
 * Password Strength Analyzer Engine
 * Computes entropy, vulnerability penalties, crack times, and actionable recommendations.
 */

class PasswordAnalyzer {
  constructor() {
    this.hasLower = false;
    this.hasUpper = false;
    this.hasNumber = false;
    this.hasSymbol = false;
  }

  analyze(password) {
    if (!password || password.length === 0) {
      return this.getEmptyResult();
    }

    const len = password.length;
    const lowerCount = (password.match(/[a-z]/g) || []).length;
    const upperCount = (password.match(/[A-Z]/g) || []).length;
    const numberCount = (password.match(/[0-9]/g) || []).length;
    const symbolCount = (password.match(/[^a-zA-Z0-9]/g) || []).length;

    this.hasLower = lowerCount > 0;
    this.hasUpper = upperCount > 0;
    this.hasNumber = numberCount > 0;
    this.hasSymbol = symbolCount > 0;

    // Character pool calculation
    let poolSize = 0;
    if (this.hasLower) poolSize += 26;
    if (this.hasUpper) poolSize += 26;
    if (this.hasNumber) poolSize += 10;
    if (this.hasSymbol) poolSize += 33;

    // Shannon Information Entropy (bits): H = L * log2(R)
    let entropy = poolSize > 0 ? len * (Math.log2(poolSize)) : 0;

    // Unique characters ratio
    const uniqueChars = new Set(password).size;
    const uniqueRatio = uniqueChars / len;

    // Detect vulnerabilities
    const vulnerabilities = [];
    const suggestions = [];
    let penalty = 0;

    const lowerPw = password.toLowerCase();

    // 1. Common password check
    if (COMMON_PASSWORDS && (COMMON_PASSWORDS.has(lowerPw) || COMMON_PASSWORDS.has(password))) {
      vulnerabilities.push("Direct match with known commonly leaked passwords!");
      penalty += 45;
    }

    // 2. Contains common subword
    if (lowerPw.includes("password") || lowerPw.includes("admin") || lowerPw.includes("qwerty") || lowerPw.includes("123456")) {
      vulnerabilities.push("Contains predictable common terms ('password', 'admin', 'qwerty', or '123456').");
      penalty += 25;
    }

    // 3. Repeated sequences (e.g. 'aaaa', '1111')
    if (/(.)\1{2,}/.test(password)) {
      vulnerabilities.push("Contains identical repeated characters (e.g., 'aaa').");
      penalty += 15;
    }

    // 4. Sequential patterns
    if (this.hasSequentialChars(password)) {
      vulnerabilities.push("Contains sequential alphabet or numeric patterns (e.g., '123', 'abc').");
      penalty += 15;
    }

    // 5. Low variety
    if (uniqueRatio < 0.6 && len > 5) {
      vulnerabilities.push("High character repetition; low unique character diversity.");
      penalty += 10;
    }

    // Suggestions generation
    if (len < 12) {
      suggestions.push(`Make it longer! Aim for at least 12–16 characters (current: ${len}). Length is the #1 defense against brute force.`);
    }
    if (!this.hasUpper) {
      suggestions.push("Include uppercase letters (A-Z) to expand the search space.");
    }
    if (!this.hasLower) {
      suggestions.push("Include lowercase letters (a-z).");
    }
    if (!this.hasNumber) {
      suggestions.push("Add numerical digits (0-9) interspersed naturally.");
    }
    if (!this.hasSymbol) {
      suggestions.push("Add special symbols (e.g., ! @ # $ % ^ & *) to exponentially increase complexity.");
    }
    if (vulnerabilities.length > 0 && suggestions.length < 3) {
      suggestions.push("Use an uncommon passphrase of 4 or more random words (e.g., 'cactus-nebula-falcon-7').");
    }

    // Calculate effective score out of 100
    // Based on length, variety, entropy and penalties
    let rawScore = 0;
    
    // Length contribution (max 40 pts)
    if (len >= 16) rawScore += 40;
    else if (len >= 12) rawScore += 32;
    else if (len >= 8) rawScore += 20;
    else rawScore += len * 2;

    // Variety contribution (max 30 pts)
    const varietyCount = [this.hasLower, this.hasUpper, this.hasNumber, this.hasSymbol].filter(Boolean).length;
    rawScore += varietyCount * 7.5;

    // Entropy contribution (max 30 pts)
    if (entropy > 80) rawScore += 30;
    else if (entropy > 60) rawScore += 24;
    else if (entropy > 40) rawScore += 16;
    else rawScore += (entropy / 40) * 16;

    // Apply penalties
    let finalScore = Math.max(0, Math.min(100, Math.round(rawScore - penalty)));

    // Categorization
    let statusLabel = "Very Weak";
    let statusColor = "#ef4444"; // red
    let statusBadgeClass = "badge-danger";

    if (finalScore >= 85) {
      statusLabel = "Very Strong";
      statusColor = "#10b981"; // emerald
      statusBadgeClass = "badge-very-strong";
    } else if (finalScore >= 65) {
      statusLabel = "Strong";
      statusColor = "#06b6d4"; // cyan
      statusBadgeClass = "badge-strong";
    } else if (finalScore >= 45) {
      statusLabel = "Moderate";
      statusColor = "#f59e0b"; // amber
      statusBadgeClass = "badge-moderate";
    } else if (finalScore >= 25) {
      statusLabel = "Weak";
      statusColor = "#f97316"; // orange
      statusBadgeClass = "badge-weak";
    }

    // Crack time estimations
    // Total combinations = poolSize ^ len
    // With penalties, effective combinations may be reduced
    const effectiveEntropy = Math.max(1, entropy - (penalty * 0.5));
    const combinations = Math.pow(2, effectiveEntropy);

    const crackTimes = {
      onlineThrottled: this.formatTime(combinations / (100 / 3600)), // 100/hr = ~0.028/s
      onlineFast: this.formatTime(combinations / 1000),             // 1,000/s
      offlineSlow: this.formatTime(combinations / 10000),           // 10,000/s (bcrypt/Argon2)
      offlineFast: this.formatTime(combinations / 1e11)             // 100 billion/s (High-end GPU array)
    };

    return {
      password,
      length: len,
      poolSize,
      entropy: Math.round(entropy * 10) / 10,
      uniqueChars,
      score: finalScore,
      statusLabel,
      statusColor,
      statusBadgeClass,
      criteria: {
        length8: len >= 8,
        length12: len >= 12,
        hasLower: this.hasLower,
        hasUpper: this.hasUpper,
        hasNumber: this.hasNumber,
        hasSymbol: this.hasSymbol,
        noRepeats: !/(.)\1{2,}/.test(password),
        noCommon: !COMMON_PASSWORDS.has(lowerPw) && !COMMON_PASSWORDS.has(password)
      },
      vulnerabilities,
      suggestions,
      crackTimes
    };
  }

  hasSequentialChars(str) {
    const s = str.toLowerCase();
    for (let i = 0; i < s.length - 2; i++) {
      const c1 = s.charCodeAt(i);
      const c2 = s.charCodeAt(i + 1);
      const c3 = s.charCodeAt(i + 2);
      if (c2 === c1 + 1 && c3 === c2 + 1) return true;
      if (c2 === c1 - 1 && c3 === c2 - 1) return true;
    }
    return false;
  }

  formatTime(seconds) {
    if (seconds <= 0 || !isFinite(seconds)) return "Instant (< 1 ms)";
    if (seconds < 1) return "Instant (< 1 sec)";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
    if (seconds < 31536000 * 1000000) return `${(seconds / 31536000).toLocaleString(undefined, { maximumFractionDigits: 0 })} years`;
    if (seconds < 31536000 * 1e12) return `${(seconds / (31536000 * 1e6)).toFixed(1)} million years`;
    if (seconds < 31536000 * 1e15) return `${(seconds / (31536000 * 1e9)).toFixed(1)} billion years`;
    return "Centuries of trillions of years (Virtually Unbreakable)";
  }

  getEmptyResult() {
    return {
      password: "",
      length: 0,
      poolSize: 0,
      entropy: 0,
      uniqueChars: 0,
      score: 0,
      statusLabel: "Empty",
      statusColor: "#6b7280",
      statusBadgeClass: "badge-empty",
      criteria: {
        length8: false,
        length12: false,
        hasLower: false,
        hasUpper: false,
        hasNumber: false,
        hasSymbol: false,
        noRepeats: true,
        noCommon: true
      },
      vulnerabilities: [],
      suggestions: [
        "Type or generate a password above to begin your security assessment.",
        "Aim for a minimum length of 12+ characters.",
        "Combine uppercase, lowercase, numbers, and symbols."
      ],
      crackTimes: {
        onlineThrottled: "Instant",
        onlineFast: "Instant",
        offlineSlow: "Instant",
        offlineFast: "Instant"
      }
    };
  }
}

window.passwordAnalyzer = new PasswordAnalyzer();
