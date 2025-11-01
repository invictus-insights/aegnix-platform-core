import logging, json, sys, time, os


def get_logger(name="aegnix", level=logging.INFO, to_file=None):
    """Unified structured logger for all AEGNIX components."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt=json.dumps({
                "ts": "%(asctime)s",
                "level": "%(levelname)s",
                "name": "%(name)s",
                "msg": "%(message)s"
            }),
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        formatter.converter = time.gmtime  # Use UTC timestamps
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        if to_file:
            # Ensure the directory exists before writing
            os.makedirs(os.path.dirname(to_file), exist_ok=True)
            file_handler = logging.FileHandler(to_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
