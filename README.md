# 🏫 School Management API

A high-performance, type-safe backend service built with **Rust** and **Axum**. This project implements a structured learning management system focusing on student applications, mentor interventions, and GitHub-based assignment workflows.

## 🏗 Architecture
The project follows a **Layered Architecture** to ensure clean separation of concerns and maintainability:

* **`src/routes/`**: Endpoint definitions and routing logic.
* **`src/controllers/`**: Request handling, payload validation, and response mapping.
* **`src/services/`**: Core business logic (e.g., application status transitions, GitHub API calls).
* **`src/models/`**: Data structures representing **Users** and **Schools**, including SQLx integration.
* **`src/middleware/`**: Logic for authentication, logging, and network-specific validation.
* **`src/utils/`**: Shared utilities for barcode generation and JWT handling.
* **`src/error.rs`**: Centralized error types converted into HTTP responses.

---

## 🛠 Tech Stack
* **Language**: Rust (Edition 2021)
* **Web Framework**: [Axum](https://github.com/tokio-rs/axum)
* **Runtime**: [Tokio](https://tokio.rs/)
* **Database**: PostgreSQL + [SQLx](https://github.com/launchbadge/sqlx) (Compile-time verified queries)
* **Serialization**: Serde (JSON)
* **Integration**: GitHub API (via `octocrab`)

---

## 🚀 Getting Started

### Prerequisites
* [Rust](https://www.rust-lang.org/tools/install) (latest stable)
* [PostgreSQL](https://www.postgresql.org/)
* `sqlx-cli` (Install via `cargo install sqlx-cli --no-default-features --features postgres`)

### Environment Setup
Create a `.env` file in the root directory:
```env
DATABASE_URL=postgres://user:password@localhost:5432/school_db
PORT=8080
GITHUB_TOKEN=your_github_personal_access_token
