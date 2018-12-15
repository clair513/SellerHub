import os
import logging
from datetime import datetime

# Importing internal module dependency:
from sellerhub.config import BaseConfig


def setup_logging(config_name="default"):
    """
    Setting up logging to console (INFO+) and logging of log file
    logs/app-<timestamp>.log. Additionally, we can create an extra logger to represent
    certain areas in our app like: logger1 = logging.getLogger("area1")

    Logging Levels:(Follow_Guide --> https://docs.python.org/3/howto/logging.html#logging-levels)
    > DEBUG (default for FILE): Detailed information, typically of interest only when diagnosing problems.
    > INFO (default for CONSOLE): Confirmation that things are working as expected.
    > WARNING: An indication that something unexpected happened, or indicative of some problem in the near future (e.g. "Low Disk space"). So our software is still working as expected.
    > ERROR: Due to a more serious problem, the software has not been able to perform some function.
    > CRITICAL: A serious error, indicating that our program itself may not be able to continue running.

    Parameters: 'config_name' --> By default set to 'BaseConfig'.
    """

    # Ensuring the 'logs' folder exists (to avoid 'FileNotFound' Error):
    if not os.path.isdir("logs"):
        os.makedirs("logs")

    # Setting the logging levels:
    log_lvl_file = "DEBUG"
    log_lvl_console = "INFO"

    if config_name == "development":
        log_lvl_console = "DEBUG"
    elif config_name == "production":
        log_lvl_file = "INFO"

    # Set up logging to a file (overwriting):
    log_filename = ("logs/sellerhub - {}.log".format(datetime.utcnow().strftime("%Y%m%d")))

    # Possibly good to use ''%(pathname)s:%(lineno)d':
    logging.basicConfig(format="%(asctime)s.%(msecs)03d - %(name)-12s - "
                               "%(levelname)-8s - %(message)s",
                        datefmt= "%Y-%m-%d %H:%M:%S",
                        filename= log_filename,
                        filemode= "w",
                        level= log_lvl_file)

    # Creating a handler to writes INFO messages or higher to 'sys.stderr':
    console = logging.StreamHandler()
    console.setLevel(log_lvl_console)

    # Create a formatter without timestamp for the console handler
    console_formatter = logging.Formatter("%(name)-12s - %(levelname)-8s - %(message)s")

    # Adding formatter to Console handler:
    console.setFormatter(console_formatter)

    # Adding Console handler to root logger:
    logging.getLogger("").addHandler(console)

    """
    [DEMO USAGE]:
    logger = logging.getLogger("setup_logging")

    logger.debug("a debug log message")
    logger.info("an info log message")
    logger.warning("a warning log message")
    logger.error("an error log message")
    logger.critical("a critical log message")
    """
