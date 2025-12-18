```markdown
# Password Authentication Research Project

This project implements a demo environment for testing password-based authentication mechanisms and simulating attacks such as **Brute-Force** and **Password-Spraying** under different defense configurations.  
Developed as part of course 20940 (*מבוא לאבטחת המרחב המקוון*).

---

## GROUP_SEED
`532645069`  
This seed uniquely identifies our group and is included in logs and configuration files for reproducibility.

---

## Password Categories in `users.json`

To simulate realistic attack scenarios, we divided users into three categories:

### Weak Passwords
- **Examples:** `123456`, `mypassword`, `admin`
- Represent common insecure choices made for convenience.  
- Easily guessed and quickly cracked under brute force or spraying.

### Medium Passwords
- **Examples:** `TelAviv2025`, `Israel2025`
- Stronger than trivial passwords but still predictable (dictionary words + numbers).  
- Vulnerable to spraying and dictionary attacks.  

### Strong Passwords
- **Examples:** `T0qL%vN3p$W8zY!r`
- Long, random, mixed characters and symbols.  
- Resistant to brute force even with fast hashing.  
- Demonstrates maximum security when combined with layered defenses.  

---

## Demo Test App

We created a demo Flask app to simulate authentication endpoints and defenses.

### Endpoints
- `/register` – Register new users.  
- `/login` – Standard login with password.  
- `/login_totp` – Login with password + TOTP.  

---

## Installation & Setup

1. **Clone the repository**  
   ```bash
   git clone <repo-url>
   cd <repo-dir>
   ```

2. **Create a virtual environment**  
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/Mac
   venv\Scripts\activate      # Windows
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

   ### Dependencies
   - Flask==3.0.2  
   - bcrypt==4.1.2  
   - argon2-cffi==23.1.0  
   - requests==2.31.0  
   - pyotp==2.9.0  
   - pandas==2.2.2  

4. **Run the demo server**  
   ```bash
   python -m app.routes
   ```

5. **Run attack scripts**  
   - Brute force:  
     ```bash
     python -m scripts.brute_force <username>
     ```
   - Password spraying:  
     ```bash
     python -m scripts.password_spraying
     ```
   - Analyze logs:  
     ```bash
     python -m scripts.analyze_logs
     ```

---

## Project Structure

```
app/
  routes.py        # Flask endpoints
  config.py        # Defense toggles, pepper, GROUP_SEED
data/
  users.json       # Test users (weak/medium/strong)
  rockyou.txt      # Wordlist for attacks (large file, see .gitignore note)
logs/
  attempts.log     # Raw JSON logs of all attack attempts
scripts/
  brute_force.py   # Brute force attack simulation
  password_spray.py# Password spraying simulation
  analyze_logs.py  # Summarize results
requirements.txt   # Python dependencies
README.md          # Documentation
```

---

## Files Required but Ignored in Git

Some files are **needed for experiments** but should not be committed to Git for size, reproducibility, or privacy reasons.  
Make sure they exist locally before running:

- `data/rockyou.txt` – large password wordlist used for brute force and spraying.  
- `logs/attempts.log` – raw logs generated during experiments.  
- `.env` – environment variables (e.g., pepper secret).  
- `venv/` – local virtual environment.  
- `__pycache__/` – Python cache files.  

Add these to `.gitignore` but ensure they are present locally when running experiments.

---

## Usage Notes
- All experiments must be run locally in a controlled environment.  
- Do **not** use real user data or external systems.  
```

---