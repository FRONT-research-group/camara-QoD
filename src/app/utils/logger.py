import logging

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
        logger.setLevel(logging.DEBUG)  # Allow all log levels from DEBUG and above

        # Define log format
        formatter = ColoredFormatter(
            '%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d:%H:%M:%S'
        )

        # Console stream handler for DEBUG and above
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG)  # Show debug logs in console too
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger
