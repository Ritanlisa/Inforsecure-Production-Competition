# coding:UTF-8


import os


DEBUG = True

WTF_CSRF_ENABLED = False

SECRET_KEY = '!@#$%8F6F98EC3684AECA1DC44E1CB816E4A5^&*()'

# if current os is linux
if os.name == 'posix':
    UPLOAD_FOLDER = '/home/IPC/PCAP/'
    FILE_FOLDER = '/home/IPC/Files/'
    PDF_FOLDER = '/home/IPC/Files/PDF/'
    WORKFLOW_FOLDER = '/home/IPC/Files/Workflow/'
    NETWORK_FOLDER = '/home/IPC/Files/Network/'
    CICFLOWMETER_PATH = '/home/IPC/CICFlowMeter-4.0/bin/cfm'
    CSV_FOLDER = '/home/IPC/Files/CSV/'
elif os.name == 'nt':
    UPLOAD_FOLDER = './PCAP/'
    FILE_FOLDER = './Files/'
    PDF_FOLDER = './PDF/'
    WORKFLOW_FOLDER = './Workflow/'
    NETWORK_FOLDER = './network/'
    LOG_FOLDER = './log/'
    CICFLOWMETER_PATH = './CICFlowMeter-4.0/bin/cfm'
    CSV_FOLDER = './CSV/'
