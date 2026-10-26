"""The web process: receives GitHub webhooks, nothing else."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code.app.webhooks import router
from newsoc_code.config import Settings, get_settings
from newsoc_code.db.session import make_engine, make_session_factory


def create_app(
    settings: Settings | None = None,
    *,
    session_factory: sessionmaker[Session] | None = None,
    webhook_secret: bytes | None = None,
    app_id: int | None = None,
) -> FastAPI:
    """Build the app. Arguments override settings so tests can inject a database and secret.

    Run with ``uvicorn --factory newsoc_code.app.main:create_app``.
    """
    settings = settings or get_settings()
    app = FastAPI(title="newsoc", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.webhook_secret = webhook_secret or settings.webhook_secret()  # fail fast if missing
    app.state.app_id = app_id if app_id is not None else settings.github_app_id
    app.state.session_factory = session_factory or make_session_factory(
        make_engine(settings.database_url)
    )
    app.include_router(router)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        try:
            with app.state.session_factory() as session:
                session.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    return app
