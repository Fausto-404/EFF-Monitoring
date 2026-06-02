from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin, ai, alerts, assets, auth, imports, messages, ops, reports, rules, settings, templates
from app.core.settings import get_settings
from app.models.bootstrap import bootstrap_defaults
from app.models.database import Base, SessionLocal, engine


def create_app() -> FastAPI:
    cfg = get_settings()
    app = FastAPI(
        title=cfg.app_name,
        contact={
            "name": "Fausto",
            "url": "https://github.com/Fausto-404/EFF-Monitoring",
        }
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router, prefix=cfg.api_prefix)
    app.include_router(admin.router, prefix=cfg.api_prefix)
    app.include_router(ai.router, prefix=cfg.api_prefix)
    app.include_router(alerts.parse_router, prefix=cfg.api_prefix)
    app.include_router(alerts.router, prefix=cfg.api_prefix)
    app.include_router(assets.router, prefix=cfg.api_prefix)
    app.include_router(rules.router, prefix=cfg.api_prefix)
    app.include_router(templates.router, prefix=cfg.api_prefix)
    app.include_router(reports.router, prefix=cfg.api_prefix)
    app.include_router(settings.router, prefix=cfg.api_prefix)
    app.include_router(messages.router, prefix=cfg.api_prefix)
    app.include_router(ops.router, prefix=cfg.api_prefix)
    app.include_router(imports.router, prefix=cfg.api_prefix)

    @app.on_event("startup")
    def startup() -> None:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            bootstrap_defaults(db)
        finally:
            db.close()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        return {"status": "ready"}

    return app


app = create_app()
