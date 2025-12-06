GROUPSEED =  532645069

## The reasoning behind the password categories in `users.json`

In order to simulate realistic attack scenarios, we divided users.json into three password categories. It allows us to measure how different algorithms and defenses perform.

### Weak Passwords
- **Examples:** `123456`, `mypassword`, `admin`
- **Reasoning:**
  - It represents typical insecure choices made by users for convenience reasons.
  - Easily guessed passwords.
  - They are used to demonstrate how quickly accounts with weak password get "hacked" under brute force or spraying attacks.

### Medium Passwords
- **Examples:** `TelAviv2025`, `Israel2025`
- **Reasoning:**
  - It represents users who make an effort to strengthen their passwords but rely on predictable patterns that are still guessable.
  - Vulnerable to dictionary attacks and password spraying due to common words with minor variations.
  - Useful for testing defenses like pepper and lockout, where the password is not trivially weak but still crackable.

### Strong Passwords
- **Examples:** `T0qL%vN3p$W8zY!r`
- **Reasoning:**
  - Represent best-practice security: long, random, a mix of strings and symbols.
  - Resistant to brute force even with fast hashing algorithms.
  - They provide contrast in experiments where defenses are layered, showing that strong passwords plus protections create maximum security possible.


  ## The Demo Test App
  We have created a demo app to test the attacks.
  ### How to setup
  Just run `python -m app.routes` from the main dir
  It is recomended to work with a virtual enviroment (venv). To create one just use `python -m virtualenv venv` and install the deps using `pip install -r requirements.txt`