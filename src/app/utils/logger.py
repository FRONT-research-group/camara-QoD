import logging
from app.utils.config import LOG_LEVEL

class ColoredFormatter(logging.Formatter):
    # ANSI escape codes for colors
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[41m', # Red background
    }
    RESET = '\033[0m'

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)


def get_app_logger():
    """
    Set up and return the application logger with debug support and colored output.
    """
    logger = logging.getLogger('nef_logger')
    if not logger.hasHandlers():
        # Set log level from config
        level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
        logger.setLevel(level)

        # Define log format
        formatter = ColoredFormatter(
            '%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d:%H:%M:%S'
        )

        # Console stream handler for DEBUG and above
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    return logger
