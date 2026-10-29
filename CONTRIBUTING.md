# Contributing to AuthPin

Thank you for your interest in contributing to **AuthPin**! We welcome contributions, bug reports, and suggestions.

---

## 🛠️ Prerequisites

- **Go**: Version 1.25 or higher
- **Docker**: For running integration databases (PostgreSQL, MySQL, LocalStack)
- **Make**: For executing standard automation targets

---

## 🚀 Development Workflow

1. **Clone the repository:**
   ```bash
   git clone git@github.com:divmora/authpin.git
   cd authpin
   ```

2. **Run tests:**
   ```bash
   make test
   ```

3. **Format code:**
   ```bash
   make fmt
   ```

4. **Build the binary:**
   ```bash
   make build
   ```

---

## 📋 Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` A new feature or capability
- `fix:` A bug fix
- `docs:` Documentation updates
- `test:` Adding or updating tests
- `refactor:` Code restructuring without functional changes
- `chore:` Maintenance, dependency bumps, or CI updates

---

## 📜 Licensing

By contributing to AuthPin, you agree that your contributions will be licensed under the project's **Business Source License 1.1 (BSL 1.1)**, converting to Apache 2.0 after three years from release.
