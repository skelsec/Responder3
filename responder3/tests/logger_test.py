import logging
import logging.config
import config

logging.config.dictConfig(config.logsettings['log'])
logger = logging.getLogger('Responder3')

logger.debug('a')
logger.info('b')

logger.log(logging.DEBUG, 'c')
logger.log(logging.INFO, 'd')