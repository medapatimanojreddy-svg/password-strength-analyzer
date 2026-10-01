/**
 * Cryptographically Secure Password Generator
 */

class PasswordGenerator {
  constructor() {
    this.charSets = {
      lower: "abcdefghijklmnopqrstuvwxyz",
      upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      numbers: "0123456789",
      symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?"
    };
    this.ambiguousChars = /[l1IO0o]/g;
  }

  generate(options = {}) {
    const {
      length = 16,
      useLower = true,
      useUpper = true,
      useNumbers = true,
      useSymbols = true,
      excludeAmbiguous = false
    } = options;

    let availableChars = "";
    const mandatoryChars = [];

    if (useLower) {
      let set = this.charSets.lower;
      if (excludeAmbiguous) set = set.replace(this.ambiguousChars, "");
      if (set.length > 0) {
        availableChars += set;
        mandatoryChars.push(this.getRandomChar(set));
      }
    }

    if (useUpper) {
      let set = this.charSets.upper;
      if (excludeAmbiguous) set = set.replace(this.ambiguousChars, "");
      if (set.length > 0) {
        availableChars += set;
        mandatoryChars.push(this.getRandomChar(set));
      }
    }

    if (useNumbers) {
      let set = this.charSets.numbers;
      if (excludeAmbiguous) set = set.replace(this.ambiguousChars, "");
      if (set.length > 0) {
        availableChars += set;
        mandatoryChars.push(this.getRandomChar(set));
      }
    }

    if (useSymbols) {
      let set = this.charSets.symbols;
      if (set.length > 0) {
        availableChars += set;
        mandatoryChars.push(this.getRandomChar(set));
      }
    }

    if (availableChars.length === 0) {
      availableChars = this.charSets.lower;
    }

    const result = [...mandatoryChars];
    const remainingCount = Math.max(0, length - result.length);

    // Fill remaining slots using crypto
    const randomBuffer = new Uint32Array(remainingCount);
    window.crypto.getRandomValues(randomBuffer);

    for (let i = 0; i < remainingCount; i++) {
      const idx = randomBuffer[i] % availableChars.length;
      result.push(availableChars[idx]);
    }

    // Shuffle using Fisher-Yates with crypto
    return this.shuffle(result).join("");
  }

  getRandomChar(charSet) {
    const buffer = new Uint32Array(1);
    window.crypto.getRandomValues(buffer);
    return charSet[buffer[0] % charSet.length];
  }

  shuffle(array) {
    const buffer = new Uint32Array(array.length);
    window.crypto.getRandomValues(buffer);

    for (let i = array.length - 1; i > 0; i--) {
      const j = buffer[i] % (i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
  }
}

window.passwordGenerator = new PasswordGenerator();
