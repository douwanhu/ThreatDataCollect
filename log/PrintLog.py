# coding=utf-8
import logging

logger=logging.getLogger('M-pot')
fh = logging.FileHandler('M-pot.log')
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)
logger.setLevel(logging.DEBUG)
def INFO(outputs):

    logger.info(outputs)

def ERROR(outputs):
    logger.error(outputs)
