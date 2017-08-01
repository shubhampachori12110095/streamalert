__version__ = '1.4.0'

import logging

# Create a package level logger to import
logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')
LOGGER.setLevel(logging.INFO)
