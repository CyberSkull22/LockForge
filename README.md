# Lockforge

```text
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
```

A local, offline password auditor that tells you how strong your password really is — no data sent anywhere.

## What it does

Lockforge evaluates a password across three axes:

| Check | Detail |
| --- | --- |
| **Dictionary lookup** | Matches against 4 curated wordlists (rockyou, NCSC top 100k, French top 20k, years 1900–2020) |
| **Leetspeak detection** | De-obfuscates common substitutions (`@→a`, `3→e`, `0→o`, ...) before the lookup |
| **Brute-force estimate** | Computes worst-case crack time assuming 350 GH/s (8× RTX 4090, NTLM/MD5) |

The result is a single strength label: **Weak**, **Medium**, or **Strong**.

## Strength rating

```text
Weak   — found in dictionary, or brute-forceable in under 1 hour
Medium — structural score ≥ 3, not in dictionary, not instantly crackable
Strong — structural score ≥ 5, brute-force time ≥ 1 week
```

Structural score rewards: length ≥ 8, length ≥ 12, digits, uppercase, lowercase, special characters.

## Requirements

- Python 3.10+
- No third-party dependencies

## Usage

```bash
python main.py
```

Enter your password at the prompt. Press `Ctrl+C` to quit.

```text
Enter your password (Ctrl+C to quit): hunter2
Password strength: Weak (found in dictionary)
Estimated brute-force time (NTLM, 350 GH/s): 2.1 minutes

Enter your password (Ctrl+C to quit): T!g3r_M00n#42
Password strength: Strong
Estimated brute-force time (NTLM, 350 GH/s): 1.23e+14 years
```

## Dictionary files

| File | Source |
| --- | --- |
| `rockyou.txt` | RockYou 2009 breach — classic baseline |
| `100k-most-used-passwords-NCSC.txt` | NCSC Have I Been Pwned top 100k |
| `French-common-password-list-top-20000.txt` | French common passwords top 20k |
| `1900-2020.txt` | Years 1900–2020 (common PIN/suffix pattern) |

All lookups are done locally. Your input never leaves your machine.

## License

MIT — see [LICENSE](LICENSE)

## Author

cyberskull_22
