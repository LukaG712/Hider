# Hider

> *"Everything was swell, until someone split the Dark Moon..."*
> ~ **The Dark Moon Song**, on how it all began

**Hider** is the secret and configuration management service for the Evershade ecosystem. It provides encrypted storage for API keys, passwords, and sensitive configuration data.

**Luigi's Mansion origin:** *Hider* ~ ghosts from Luigi's Mansion: Dark Moon that hide in plain sight, making them hard to find.

## Features

- **Secret Storage** ~ Encrypted at-rest storage for sensitive data
- **Configuration** ~ Centralized config with versioning
- **Access Control** ~ Per-service secret scoping

## Quick Start

```bash
docker compose up -d Hider
pip install -e ".[dev]"
python -m uvicorn hider.api:app --host 0.0.0.0 --port 8087
```

## API

- **Swagger UI:** `http://localhost:8087/docs`
- **ReDoc:** `http://localhost:8087/redoc`

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | `Hider-dev-key-change-me` | API authentication key |
| `PORT` | `8087` | Server port |
| `ENCRYPTION_KEY` | (required) | Master encryption key |

## License

MIT
