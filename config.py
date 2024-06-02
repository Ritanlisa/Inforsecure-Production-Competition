# coding:UTF-8


DEBUG = True

WTF_CSRF_ENABLED = False

SECRET_KEY = '!@#$%8F6F98EC3684AECA1DC44E1CB816E4A5^&*()'

# OpenAI API Settings
API_KEY = 'PUT_YOUR_API_KEY_HERE'
BASE_URL = 'https://api.openai.com/v1/chat/completions'
MODEL_NAME = 'gpt-3.5-turbo-1106'

import os
basedir = os.path.abspath(os.path.dirname(__file__))


UPLOAD_FOLDER = 'tmp/PCAP/'
FILE_FOLDER = 'tmp/Files/'
PDF_FOLDER = 'tmp/Files/PDF/'
CSV_FOLDER = 'tmp/Files/csv/'
NETWORK_FOLDER = 'network/'
CICFLOWMETER_PATH = 'CICFlowMeter-4.0/CICFlowMeter-4.0/bin'
LOG_FOLDER = 'logs/'

UPLOAD_FOLDER = os.path.join(basedir, UPLOAD_FOLDER)
FILE_FOLDER = os.path.join(basedir, FILE_FOLDER)
PDF_FOLDER = os.path.join(basedir, PDF_FOLDER)
CSV_FOLDER = os.path.join(basedir, CSV_FOLDER)
NETWORK_FOLDER = os.path.join(basedir, NETWORK_FOLDER)
CICFLOWMETER_PATH = os.path.join(basedir, CICFLOWMETER_PATH)
LOG_FOLDER = os.path.join(basedir, LOG_FOLDER)

# if using windows fs
if os.name == 'nt':
    UPLOAD_FOLDER = UPLOAD_FOLDER.replace('/', '\\')
    FILE_FOLDER = FILE_FOLDER.replace('/', '\\')
    PDF_FOLDER = PDF_FOLDER.replace('/', '\\')
    CSV_FOLDER = CSV_FOLDER.replace('/', '\\')
    NETWORK_FOLDER = NETWORK_FOLDER.replace('/', '\\')
    CICFLOWMETER_PATH = CICFLOWMETER_PATH.replace('/', '\\')
    LOG_FOLDER = LOG_FOLDER.replace('/', '\\')
elif os.name == 'posix':
    UPLOAD_FOLDER = UPLOAD_FOLDER.replace('\\', '/')
    FILE_FOLDER = FILE_FOLDER.replace('\\', '/')
    PDF_FOLDER = PDF_FOLDER.replace('\\', '/')
    CSV_FOLDER = CSV_FOLDER.replace('\\', '/')
    NETWORK_FOLDER = NETWORK_FOLDER.replace('\\', '/')
    CICFLOWMETER_PATH = CICFLOWMETER_PATH.replace('\\', '/')
    LOG_FOLDER = LOG_FOLDER.replace('\\', '/')
else:
    raise OSError('Unsupported operating system')