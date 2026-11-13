"""Entry point: `python app.py` starts the web UI on http://localhost:8000 (HOST/PORT configurable)."""

import uvicorn

from formbot.config import get_settings
from formbot.logging_setup import configure_logging
from formbot.main import create_app


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
