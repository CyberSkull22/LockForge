import os
import sys

'''
  ██╗      ██████╗  ██████╗██╗  ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██║     ██║   ██║██║     █████╔╝ █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██║     ██║   ██║██║     ██╔═██╗ ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ███████╗╚██████╔╝╚██████╗██║  ██╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

  ─────────────────────────────────────────────────────────────────────────────
                           [ password auditor v1.0 ]                             
                           [ forge your defense.   ]
  ─────────────────────────────────────────────────────────────────────────────
'''
DICT_DIR = os.path.join(os.path.dirname(__file__), "dictionary")
DICTIONARY_FILES = [
    "rockyou.txt",
    "French-common-password-list-top-20000.txt",
    "1900-2020.txt",
    "100k-most-used-passwords-NCSC.txt",
]

SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{}|;:'\",.<>?/")

# Modern attacker speed: fast hash (MD5/NTLM, 8x RTX 4090) — worst-case, no key stretching
ATTACK_SPEED_PER_SECOND = 350_000_000_000  # 350 GH/s

# Brute-force time thresholds used by classify() to cap the strength rating
_BF_WEAK_THRESHOLD = 3600        # under 1 hour  → Weak regardless of structure
_BF_MEDIUM_THRESHOLD = 86400 * 7 # under 1 week  → cap at Medium


def load_dictionaries() -> set[str]:
    """Load all dictionary files into a single lowercase set."""
    words: set[str] = set()
    for filename in DICTIONARY_FILES:
        path = os.path.join(DICT_DIR, filename)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                words.add(line.strip().lower())
    return words


def structural_score(password: str) -> int:
    """Score 0-6 based on length and character variety."""
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c in SPECIAL_CHARS for c in password):
        score += 1
    return score


# Leetspeak substitution table: maps obfuscation chars back to their base letter.
# Each key is replaced by its value before the dictionary lookup.
_LEET_TABLE = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
    "+": "t",
    "9": "g",
    "8": "b",
    "6": "g",
    "(": "c",
    "|": "l",
    "2": "z",
})


def _leet_variants(word: str) -> set[str]:
    """Return the original word plus its de-leeted variant."""
    return {word, word.translate(_LEET_TABLE)}


def in_dictionary(password: str, dictionary: set[str]) -> bool:
    """Return True if the password (or a common leet variant) appears in the dictionary."""
    normalized = password.lower()
    return bool(_leet_variants(normalized) & dictionary)


def charset_size(password: str) -> int:
    """Return the effective character-set size for brute-force entropy estimation."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in SPECIAL_CHARS for c in password):
        size += 32
    return size or 26  # fallback for exotic/unicode chars


def brute_force_seconds(password: str) -> float:
    """Estimate worst-case brute-force crack time in seconds (no key stretching)."""
    combinations = charset_size(password) ** len(password)
    return combinations / ATTACK_SPEED_PER_SECOND


def format_time(seconds: float) -> str:
    """Convert a duration in seconds to a human-readable string."""
    if seconds < 1:
        return "less than 1 second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31_536_000:
        return f"{seconds / 86400:.1f} days"
    elif seconds < 3_153_600_000:
        return f"{seconds / 31_536_000:.1f} years"
    else:
        return f"{seconds / 31_536_000:.2e} years"


def classify(st_score: int, found_in_dict: bool, bf_seconds: float) -> str:
    """
    Combine structural score, dictionary presence, and brute-force time into a
    single strength label.

    Dictionary hit always wins (instant crack via lookup).
    Brute-force time caps the rating: a structurally-complex but short password
    can still be cracked in seconds, so it must not be rated Strong or Medium.
    """
    if found_in_dict:
        return "Weak (found in dictionary)"
    # Even a high structural score is irrelevant if the search space is tiny.
    if bf_seconds < _BF_WEAK_THRESHOLD:
        return "Weak (brute-forceable in under 1 hour)"
    if st_score >= 5 and bf_seconds >= _BF_MEDIUM_THRESHOLD:
        return "Strong"
    if st_score >= 3:
        return "Medium"
    return "Weak"


_BANNER = r"""
  ██╗      ██████╗  ██████╗██╗  ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██║     ██║   ██║██║     █████╔╝ █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██║     ██║   ██║██║     ██╔═██╗ ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ███████╗╚██████╔╝╚██████╗██║  ██╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

  ─────────────────────────────────────────────────────────────────────────────
                           [ password auditor v1.0 ]
                           [ forge your defense.   ]
  ─────────────────────────────────────────────────────────────────────────────
"""


def main() -> None:
    print(_BANNER)
    print("Loading dictionaries...", end="\r", flush=True)
    dictionary = load_dictionaries()
    print(" " * 25, end="\r")

    while True:
        try:
            password = input("Enter your password (Ctrl+C to quit): ")
        except KeyboardInterrupt:
            print("\nBye!")
            break

        st = structural_score(password)
        found = in_dictionary(password, dictionary)
        bf_time = brute_force_seconds(password)

        strength = classify(st, found, bf_time)

        print(f"Password strength: {strength}")
        print(f"Estimated brute-force time (NTLM, 350 GH/s): {format_time(bf_time)}")
        print()


if __name__ == "__main__":
    main()
