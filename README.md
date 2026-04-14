# envault

> A CLI tool for securely managing and rotating environment variable secrets across multiple environments.

---

## Installation

```bash
pip install envault
```

Or with [pipx](https://pypa.github.io/pipx/) (recommended):

```bash
pipx install envault
```

---

## Usage

Initialize a vault in your project directory:

```bash
envault init
```

Add and retrieve secrets:

```bash
# Store a secret
envault set DATABASE_URL "postgres://user:pass@localhost/db" --env production

# Retrieve a secret
envault get DATABASE_URL --env production

# Rotate all secrets in an environment
envault rotate --env production

# Export secrets to a .env file
envault export --env staging > .env
```

List all tracked environments:

```bash
envault list
```

---

## How It Works

`envault` encrypts your secrets locally using AES-256 and stores them in a `.vault` file that can be safely committed to version control. Secrets are decrypted at runtime using a master key stored separately (e.g., in your CI/CD environment or a secrets manager).

---

## License

This project is licensed under the [MIT License](LICENSE).