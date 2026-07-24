# Code Hardener Gemini Agent Context

This document provides context for the Code Hardener codebase, enabling the Gemini agent to understand the project structure, purpose, and operational procedures.

## Project Overview

Code Hardener is a security-as-a-service platform designed for AI-first developers—individuals and teams who build applications using AI-assisted coding tools like GitHub Copilot and Cursor. The platform integrates a suite of 27 open-source security and testing tools into a unified, developer-friendly interface.

The core philosophy is to make security accessible to developers who may not have deep security expertise. It translates complex security jargon (CVEs, CWEs) into plain-language explanations and provides automated remediation suggestions.

The project is a monorepo containing three main services:

-   **`backend`**: A Node.js/TypeScript API server built with Fastify. It serves as the core of the Code Hardener platform, orchestrating security scans, managing data, and exposing a REST API.
-   **`dashboard`**: A Next.js/TypeScript web application that serves as the main user interface for the Code Hardener platform.
-   **`marketing`**: A Next.js/TypeScript public-facing website for marketing and documentation.

The services are supported by a PostgreSQL database and a Redis instance for caching and queue management.

## Building and Running the Project

The entire project is orchestrated using Docker Compose.

### Prerequisites

-   Docker and Docker Compose
-   Node.js >= 20.0.0
-   An `.env` file created from the `.env.example` template.

### Running the Full Stack

To build and run all services (backend, dashboard, marketing, postgres, redis):

```bash
docker-compose up --build
```

The services will be available at the following URLs:

-   **Marketing Site**: `http://localhost:3000`
-   **Dashboard**: `http://localhost:3001`
-   **Backend API**: `http://localhost:4000`

### Running Individual Services

Each service can be run individually for development.

#### Backend

To run the backend server in development mode with hot-reloading:

```bash
cd backend
npm install
npm run dev
```

#### Dashboard

To run the dashboard in development mode:

```bash
cd dashboard
npm install
npm run dev
```

#### Marketing

To run the marketing site in development mode:

```bash
cd marketing
npm install
npm run dev
```

## Development Conventions

### Coding Style

-   **TypeScript**: The entire codebase is written in TypeScript. Adhere to the existing style and typing conventions.
-   **ESLint**: All three projects use ESLint for code quality and style enforcement. Run `npm run lint` within each project directory to check for issues.
-   **Prettier**: Although not explicitly configured in the `package.json` scripts, the code appears to follow Prettier's default formatting.

### Testing

-   **Backend**: The backend uses `vitest` for unit and integration tests. Run tests with `npm test`.
-   **Frontend**: The frontend projects use Playwright for end-to-end tests.

### API

The backend exposes a REST API, and the frontend applications communicate with it. The API is documented using Swagger, which is available at `http://localhost:4000/docs` when the backend is running.

### Database

Database migrations and seeding are handled by scripts in the `backend` project.

-   To run migrations: `npm run db:migrate`
-   To seed the database: `npm run db:seed`
