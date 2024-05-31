# coding:UTF-8


import requests,threading
from app import app
import json
from flask import (
    render_template,
    request,
    flash,
    redirect,
    url_for,
    send_from_directory,
)
from .forms import Upload, ProtoFilter
from .utils.upload_tools import allowed_file, get_filetype, random_name
from .utils.pcap_decode import PcapDecode
from .utils.pcap_filter import get_all_pcap, proto_filter, showdata_from_id
from .utils.proto_analyzer import (
    common_proto_statistic,
    pcap_len_statistic,
    http_statistic,
    dns_statistic,
    most_proto_statistic,
)
from .utils.flow_analyzer import (
    time_flow,
    data_flow,
    get_host_ip,
    data_in_out_ip,
    proto_flow,
    most_flow_statistic,
)
from .utils.ipmap_tools import getmyip, get_ipmap, get_geo
from .utils.data_extract import (
    web_data,
    telnet_ftp_data,
    mail_data,
    sen_data,
    client_info,
)
from .utils.except_info import exception_warning
from .utils.file_extract import web_file, ftp_file, mail_file, all_files
from flask import Flask, render_template
from kamene.all import *
import numpy as np
import os
import re
import hashlib
import time

# 导入函数到模板中
app.jinja_env.globals["enumerate"] = enumerate

# 全局变量
PCAP_NAME = ""  # 上传文件名
PD = PcapDecode()  # 解析器
PCAPS = None  # 数据包
NetType = None  # 网络类型
route = None
# --------------------------------------------------------首页，上传------------
# 首页


@app.route("/", methods=["POST", "GET"])
@app.route("/index/", methods=["POST", "GET"])
def index():
    return render_template("./home/index.html")


# 数据包上传
@app.route("/upload/", methods=["POST", "GET"])
def upload():
    global route
    filepath = app.config["UPLOAD_FOLDER"]
    upload = Upload()
    if request.method == "GET":
        route = request.args.get("next")
        return render_template("./upload/upload.html")
    elif request.method == "POST":
        pcap = upload.pcap.data
        if upload.validate_on_submit():
            pcapname = pcap.filename
            if allowed_file(pcapname):
                name1 = random_name()
                name2 = get_filetype(pcapname)
                global PCAP_NAME, PCAPS
                PCAP_NAME = name1 + name2
                try:
                    if not os.path.exists(filepath):
                        os.makedirs(filepath)
                    pcap.save(os.path.join(filepath, PCAP_NAME))
                    PCAPS = rdpcap(os.path.join(filepath, PCAP_NAME))
                    flash("恭喜你,上传成功！")
                    if route:
                        target_url = url_for(route)
                        return redirect(target_url)
                    else:
                        return render_template("./upload/upload.html")
                except Exception as e:
                    flash("上传错误,错误信息:" + str(e))
                    return render_template("./upload/upload.html")
            else:
                flash("上传失败,请上传允许的数据包格式!")
                return render_template("./upload/upload.html")
        else:
            return render_template("./upload/upload.html")


@app.route("/patch/", methods=["POST", "GET"])
def patch():
    url = 'http://192.168.16.53:8080'
    filename = '123.pcap'
    flag_patch = 1

    # 用于线程间同步的事件
    stop_event = threading.Event()

    def write():
        with requests.get(url, stream=True) as response:
            with open(filename, 'ab') as file:
                for chunk in response.iter_content(chunk_size=8192): # 每次写入 8192 字节
                    if flag_patch == 0:
                        break
                    if chunk:
                        file.write(chunk)
        # 当下载完成时，设置事件
        stop_event.set()

    def read():
        global PCAPS
        while not stop_event.is_set(): # 读取过程中检查停止事件
            time.sleep(1)
            try:
                PCAPS = rdpcap(filename)
            except:
                pass
         
    with open(filename, 'w') as file:
        file.write('')

    def start_1():
        t1 = threading.Thread(target=write)
        t2 = threading.Thread(target=read)
        t1.start()
        t2.start()
    
    def stop_1():
        global flag_patch
        flag_patch = 0

    return render_template("./upload/fetch.html")

@app.route("/bgn_fetch/", methods=["POST", "GET"])
def bgn_fetch():
    return render_template("./upload/fetch.html")

@app.route("/end_fetch/", methods=["POST", "GET"])
def end_fetch():
    return render_template("./upload/fetch.html")

# -------------------------------------------数据分析--------------------------
@app.route("/basedata/", methods=["POST", "GET"])
def basedata():
    """
    基础数据解析
    """
    global PCAPS, PD
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="basedata"))
    else:
        # 将筛选的type和value通过表单获取
        filter_type = request.form.get("filter_type", type=str, default=None)
        value = request.form.get("value", type=str, default=None)
        # 如果有选择，通过选择来获取值
        if filter_type and value:
            pcaps = proto_filter(filter_type, value, PCAPS, PD)
        # 默认显示所有的协议数据
        else:
            pcaps = get_all_pcap(PCAPS, PD)
        return render_template("./dataanalyzer/basedata.html", pcaps=pcaps)


PDF_NAME = ""
# 详细数据


@app.route("/datashow/", methods=["POST", "GET"])
def datashow():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="datashow"))
    else:
        global PDF_NAME
        dataid = request.args.get("id")
        dataid = int(dataid) - 1
        data = showdata_from_id(PCAPS, dataid)
        PDF_NAME = random_name() + ".pdf"
        PCAPS[dataid].pdfdump(app.config["PDF_FOLDER"] + PDF_NAME)
        return data


# 将数据包保存为pdf


@app.route("/savepdf/", methods=["POST", "GET"])
def savepdf():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="savepdf"))
    else:
        return send_from_directory(
            app.config["PDF_FOLDER"], PDF_NAME, as_attachment=True
        )


# 协议分析
@app.route("/protoanalyzer/", methods=["POST", "GET"])
def protoanalyzer():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="protoanalyzer"))
    else:
        data_dict = common_proto_statistic(PCAPS)
        pcap_len_dict = pcap_len_statistic(PCAPS)
        pcap_count_dict = most_proto_statistic(PCAPS, PD)
        http_dict = http_statistic(PCAPS)
        http_dict = sorted(http_dict.items(), key=lambda d: d[1], reverse=False)
        http_key_list = list()
        http_value_list = list()
        for key, value in http_dict:
            http_key_list.append(key)
            http_value_list.append(value)
        dns_dict = dns_statistic(PCAPS)
        dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
        dns_key_list = list()
        dns_value_list = list()
        for key, value in dns_dict:
            dns_key_list.append(key.decode("utf-8"))
            dns_value_list.append(value)
        return render_template(
            "./dataanalyzer/protoanalyzer.html",
            data=list(data_dict.values()),
            pcap_len=pcap_len_dict,
            pcap_keys=list(pcap_count_dict.keys()),
            http_key=http_key_list,
            http_value=http_value_list,
            dns_key=dns_key_list,
            dns_value=dns_value_list,
            pcap_count=pcap_count_dict,
        )


# 流量分析
@app.route("/flowanalyzer/", methods=["POST", "GET"])
def flowanalyzer():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="flowanalyzer"))
    else:
        time_flow_dict = time_flow(PCAPS)
        host_ip = get_host_ip(PCAPS)
        data_flow_dict = data_flow(PCAPS, host_ip)
        data_ip_dict = data_in_out_ip(PCAPS, host_ip)
        proto_flow_dict = proto_flow(PCAPS)
        most_flow_dict = most_flow_statistic(PCAPS, PD)
        most_flow_dict = sorted(
            most_flow_dict.items(), key=lambda d: d[1], reverse=True
        )
        if len(most_flow_dict) > 10:
            most_flow_dict = most_flow_dict[0:10]
        most_flow_key = list()
        for key, value in most_flow_dict:
            most_flow_key.append(key)
        arp_dict = {'request': 0, 'reply': 0}  
        for pcap in PCAPS:  
            if pcap.haslayer(ARP):  
                arp = pcap.getlayer(ARP)  
                if arp.op == 1:  # ARP请求  
                    arp_dict['request'] += 1  
                elif arp.op == 2:  # ARP应答  
                    arp_dict['reply'] += 1  
        return render_template(
            "./dataanalyzer/flowanalyzer.html",
            time_flow_keys=list(time_flow_dict.keys()),
            time_flow_values=list(time_flow_dict.values()),
            data_flow=data_flow_dict,
            ip_flow=data_ip_dict,
            proto_flow=list(proto_flow_dict.values()),
            most_flow_key=most_flow_key,
            most_flow_dict=most_flow_dict,
            arp_dict=arp_dict,
        )


CVE_1 = "CVE-2013-2368"
CVE_1_title = "HP LoadRunner micWebAjax.dll ActiveX Control Stack Buffer Overflow"
CVE_1_desc = "An stack buffer overflow vulnerability exists in HP LoadRunner. The vulnerability is due to insufficient bounds checking on NotifyEvent method parameters. The application copies the parameters into a fixed size stack buffer, which can be overflowed. A remote unauthenticated attacker can exploit this vulnerability by enticing a user to visit a malicious website. Successful exploitation could allow arbitrary code execution within security context of the target user."
CVE_2 = "CVE-2013-2685"
CVE_2_title = "Digium Asterisk SIP SDP Header Parsing Stack Buffer Overflow"
CVE_2_desc = "A buffer overflow vulnerability exists in Asterisk Open Source. The vulnerability is due to insufficient boundary checking when parsing attribute strings in SIP SDP headers and allows overflowing a stack buffer with an overly long string. Remote, unauthenticated attackers could exploit this vulnerability by sending a specially crafted SIP message to the vulnerable server. Successful exploitation would cause a stack-based buffer overflow that could allow the attacker to execute arbitrary code on the vulnerable system."
CVE_3 = "CVE-2008-2939"
CVE_3_title = (
    "Apache HTTP Server mod_proxy_ftp Wildcard Characters Cross-Site Scripting"
)
CVE_3_desc = "There exist a cross-site scripting vulnerability in Apache mod_proxy_ftp module. The flaw is due to lack of sanitization of user supplied input data. The flaw may be exploited by malicious users to execute arbitrary HTML code on target user's web browser, within the context of a trusted web site."
CVE_4 = "CVE-2011-1653"
CVE_4_title = "CA Total Defense Suite UNCWS UnassignFunctionalRoles Stored Procedure SQL Injection"
CVE_4_desc = "A SQL Injection vulnerability exists in CA Total Defense Suite that can be reached through the remote web service call UnAssignFunctionalUsers. The vulnerability is due to insufficient handling of the request's modifiedData parameter. The stored procedure uncsp_UnassignFunctionalRoles uses this value in a dynamic SQL statement without any input validation. Any injected SQL commands will run with DBA privileges. This vulnerability can be leveraged by a remote unauthenticated attacker to execute arbitrary code on a target system with SYSTEM privileges by the means of SQL exec function."


# 获得文件
@app.route(("/file"), methods=["POST", "GET"])
def get_workflow():
    filename = request.args.get("filename")
    allowed_files = []
    if filename in allowed_files:
        return send_from_directory(
            app.config["WORKFLOW_FOLDER"], filename, as_attachment=True
        )
    else:
        return render_template("./error/404.html")


# 漏洞利用
@app.route(("/bug_detect/"), methods=["POST", "GET"])
def bug_detect():
    return render_template(
        "./DLVisibility/bug_detect.html",
        webdata=[
            [
                "2020/08/24 19:25:37",
                "192.168.43.119",
                "192.168.43.23",
                "8088",
                "33125",
                CVE_1,
                CVE_1_title,
                CVE_1_desc,
                "../file1",
            ],
            [
                "2020/08/24 19:26:13",
                "192.168.43.132",
                "192.168.43.23",
                "8086",
                "13325",
                CVE_2,
                CVE_2_title,
                CVE_2_desc,
                "../file2",
            ],
            [
                "2020/08/24 19:27:10",
                "192.168.43.141",
                "192.168.43.23",
                "8086",
                "13326",
                CVE_3,
                CVE_3_title,
                CVE_3_desc,
                "../file3",
            ],
            [
                "2020/08/29 19:29:05",
                "192.168.43.85",
                "192.168.43.23",
                "3600",
                "10278",
                CVE_4,
                CVE_4_title,
                CVE_4_desc,
                "../file4",
            ],
        ],
        flag=" (示例)",
    )


# 访问地图
@app.route("/ipmap/", methods=["POST", "GET"])
def ipmap():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="ipmap"))
    else:
        myip = getmyip()
        if myip:
            host_ip = get_host_ip(PCAPS)
            ipdata = get_ipmap(PCAPS, host_ip)
            geo_dict = ipdata[0]
            ip_value_list = ipdata[1]
            myip_geo = get_geo(myip)
            ip_value_list = [
                (list(d.keys())[0], list(d.values())[0]) for d in ip_value_list
            ]
            return render_template(
                "./dataanalyzer/ipmap.html",
                geo_data=geo_dict,
                ip_value=ip_value_list,
                mygeo=myip_geo,
            )
        else:
            return render_template("./error/neterror.html")


# ----------------------------------------------基于深度学习的数据分类---------------------------------------------
# subMapOfFlowAnalysis
@app.route("/sub_FlowAnalysis/", methods=["POST", "GET"])
def sub_FlowAnalysis():
    title = request.args.get("title")
    if NetType == None:
        flash("请先选择网络类型!")
        return redirect(url_for("select_method", next="sub_FlowAnalysis"))
    else:
        netFolder = app.config["NETWORK_FOLDER"]
        current_netFolder = os.path.join(netFolder, NetType)
        analysed_json = os.path.join(current_netFolder, "流量分类.json")
        if not os.path.exists(current_netFolder):
            os.makedirs(current_netFolder)
        if not os.path.exists(analysed_json):
            flow = [
                {
                    "id": 1,
                    "source": "qq",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "proto": "TCP",
                    "sport": 80,
                    "dport": 8080,
                    "len": 100,
                    "time": "2021-01-01 00:00:00",
                },
                {
                    "id": 2,
                    "source": "qq",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "proto": "TCP",
                    "sport": 80,
                    "dport": 8080,
                    "len": 100,
                    "time": "2021-01-01 00:00:00",
                },
                {
                    "id": 3,
                    "source": "wechat",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "proto": "TCP",
                    "sport": 80,
                    "dport": 8080,
                    "len": 100,
                    "time": "2021-01-01 00:00:00",
                },
            ]
            with open(analysed_json, "w", encoding="utf-8") as f:
                json.dump(flow, f)
        else:
            with open(analysed_json, "r", encoding="utf-8") as f:
                flow = json.load(f)
        subList = []
        for data in flow:
            if title == None or data["source"] == title:
                subList.append(data)
        dispNameFolder = os.path.join(netFolder, "流量分类显示名称.json")
        if not os.path.exists(dispNameFolder):
            dispName = {
                "id": "ID",
                "source": "来源",
                "src_ip": "源IP",
                "dst_ip": "目的IP",
                "proto": "协议",
                "sport": "源端口",
                "dport": "目的端口",
                "len": "报文长度",
                "time": "时间",
            }
            with open(dispNameFolder, "w", encoding="utf-8") as f:
                json.dump(dispName, f)
        else:
            with open(dispNameFolder, "r", encoding="utf-8") as f:
                dispName = json.load(f)
        return render_template(
            "./DLVisibility/table.html",
            data=subList,
            dispName=dispName,
            title=f"{title}源流量列表" if title != None else "流量列表",
        )


# log_view
@app.route("/log_view/", methods=["POST", "GET"])
def log_view():
    netFolder = app.config["NETWORK_FOLDER"]
    logfile = os.path.join(netFolder, "log.log")
    if not os.path.exists(netFolder):
        os.makedirs(netFolder)
    if not os.path.exists(logfile):
        log = []
        with open(logfile, "w", encoding="utf-8") as f:
            f.write("")
    else:
        with open(logfile, "r", encoding="utf-8") as f:
            logText = f.read()
            regex = r"\[(.*?),(.*?)\] (.*?)\n"
            # match all simple log & add to logList
            log = []
            for res in re.findall(regex, logText):
                log.append({"time": res[0], "level": res[1], "content": res[2]})
    dispName = {
        "time": "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;日志时间&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",
        "level": "&nbsp;&nbsp;日志等级&nbsp;&nbsp;",
        "content": "内容",
    }
    return render_template(
        "./DLVisibility/table.html",
        data=log,
        dispName=dispName,
        title="日志列表",
    )


# feature_extract
@app.route("/feature_extract/", methods=["POST", "GET"])
def feature_extract():
    if PCAPS == None:
        flash("请先选择PCAP包!")
        return redirect(url_for("upload", next="feature_extract"))
    else:
        pcap_path = os.path.join(app.config["UPLOAD_FOLDER"], PCAP_NAME)
        cfm_path = os.path.join(app.config["CICFLOWMETER_PATH"], "cfm.bat")
        csv_path = app.config["CSV_FOLDER"]
        if not os.path.exists(csv_path):
            os.makedirs(csv_path)
        csv_path = os.path.join(csv_path, ".".join(PCAP_NAME.split(".")[:-1]))
        if os.name == "posix":
            os.system(
                f'bash "{cfm_path}" "{pcap_path}" "{csv_path}" 1> /dev/null 2> /dev/null'
            )
        else:
            os.system(f'call "{cfm_path}" "{pcap_path}" "{csv_path}" 1> nul 2> nul')

        analysed_data = []
        for root, dirs, files in os.walk(csv_path):
            for file in files:
                if file.endswith(".csv"):
                    with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                        titles = f.readline().strip().split(",")
                        for line in f.readlines():
                            item = line.strip().split(",")
                            if len(item) > 0:
                                analysed_data.append(dict(zip(titles, item)))
        dispName = {
            "Flow ID": "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;流ID&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",
            "Src IP": "源IP",
            "Src Port": "源端口",
            "Dst IP": "目的IP",
            "Dst Port": "目的端口",
            "Protocol": "协议",
            "Timestamp": "时间戳",
            "Flow Duration": "流时长",
            "Total Fwd Packet": "总前向报文数",
            "Total Bwd packets": "总后向报文数",
            "Total Length of Fwd Packet": "总前向报文长度",
            "Total Length of Bwd Packet": "总后向报文长度",
            "Fwd Packet Length Max": "前向报文最大长度",
            "Fwd Packet Length Min": "前向报文最小长度",
            "Fwd Packet Length Mean": "前向报文平均长度",
            "Fwd Packet Length Std": "前向报文长度标准差",
            "Bwd Packet Length Max": "后向报文最大长度",
            "Bwd Packet Length Min": "后向报文最小长度",
            "Bwd Packet Length Mean": "后向报文平均长度",
            "Bwd Packet Length Std": "后向报文长度标准差",
            "Flow Bytes/s": "流量字节数/秒",
            "Flow Packets/s": "流量报文数/秒",
            "Flow IAT Mean": "流间平均时间",
            "Flow IAT Std": "流间时间标准差",
            "Flow IAT Max": "流间最大时间",
            "Flow IAT Min": "流间最小时间",
            "Fwd IAT Total": "前向平均时间",
            "Fwd IAT Mean": "前向平均时间",
            "Fwd IAT Std": "前向时间标准差",
            "Fwd IAT Max": "前向最大时间",
            "Fwd IAT Min": "前向最小时间",
            "Bwd IAT Total": "后向平均时间",
            "Bwd IAT Mean": "后向平均时间",
            "Bwd IAT Std": "后向时间标准差",
            "Bwd IAT Max": "后向最大时间",
            "Bwd IAT Min": "后向最小时间",
            "Fwd PSH Flags": "前向PSH标志数",
            "Bwd PSH Flags": "后向PSH标志数",
            "Fwd URG Flags": "前向URG标志数",
            "Bwd URG Flags": "后向URG标志数",
            "Fwd Header Length": "前向首部长度",
            "Bwd Header Length": "后向首部长度",
            "Fwd Packets/s": "前向报文数/秒",
            "Bwd Packets/s": "后向报文数/秒",
            "Packet Length Min": "报文最小长度",
            "Packet Length Max": "报文最大长度",
            "Packet Length Mean": "报文平均长度",
            "Packet Length Std": "报文长度标准差",
            "Packet Length Variance": "报文长度方差",
            "FIN Flag Count": "FIN标志数",
            "SYN Flag Count": "SYN标志数",
            "RST Flag Count": "RST标志数",
            "PSH Flag Count": "PSH标志数",
            "ACK Flag Count": "ACK标志数",
            "URG Flag Count": "URG标志数",
            "CWE Flag Count": "CWE标志数",
            "ECE Flag Count": "ECE标志数",
            "Down/Up Ratio": "下行/上行比率",
            "Average Packet Size": "报文平均大小",
            "Fwd Segment Size Avg": "前向分段平均大小",
            "Bwd Segment Size Avg": "后向分段平均大小",
            "Fwd Bytes/Bulk Avg": "前向字节数/大包平均数",
            "Fwd Packet/Bulk Avg": "前向报文数/大包平均数",
            "Fwd Bulk Rate Avg": "前向大包速率平均数",
            "Bwd Bytes/Bulk Avg": "后向字节数/大包平均数",
            "Bwd Packet/Bulk Avg": "后向报文数/大包平均数",
            "Bwd Bulk Rate Avg": "后向大包速率平均数",
            "Subflow Fwd Packets": "子流前向报文数",
            "Subflow Fwd Bytes": "子流前向字节数",
            "Subflow Bwd Packets": "子流后向报文数",
            "Subflow Bwd Bytes": "子流后向字节数",
            "FWD Init Win Bytes": "前向初始窗口字节数",
            "Bwd Init Win Bytes": "后向初始窗口字节数",
            "Fwd Act Data Pkts": "前向活动数据报文数",
            "Fwd Seg Size Min": "前向分段最小大小",
            "Active Mean": "活跃平均值",
            "Active Std": "活跃标准差",
            "Active Max": "活跃最大值",
            "Active Min": "活跃最小值",
            "Idle Mean": "空闲平均值",
            "Idle Std": "空闲标准差",
            "Idle Max": "空闲最大值",
            "Idle Min": "空闲最小值",
            "http_url": "HTTP URL",
            "http_cookies": "HTTP Cookies",
            "total_length": "总长度",
            "http_get_cnt": "HTTP GET次数",
            "http_post_cnt": "HTTP POST次数",
            "http_http_cnt": "HTTP/HTTPS次数",
            "post_payload": "POST负载",
            "Label": "标签",
        }
        return render_template(
            "./DLVisibility/table.html",
            data=analysed_data,
            dispName=dispName,
            title="提取特征列表",
        )


# flow_analyse
@app.route("/flow_analyse/", methods=["POST", "GET"])
def flow_analyse():
    if NetType == None:
        flash("请先选择网络类型!")
        return redirect(url_for("select_method", next="flow_analyse"))
    else:
        netFolder = app.config["NETWORK_FOLDER"]
        current_netFolder = os.path.join(netFolder, NetType)
        analysed_json = os.path.join(current_netFolder, "流量分类.json")
        if not os.path.exists(current_netFolder):
            os.makedirs(current_netFolder)
        if not os.path.exists(analysed_json):
            flow = [
                {
                    "id": 1,
                    "source": "qq",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "proto": "TCP",
                    "sport": 80,
                    "dport": 8080,
                    "len": 100,
                    "time": "2021-01-01 00:00:00",
                },
                {
                    "id": 2,
                    "source": "qq",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "proto": "TCP",
                    "sport": 80,
                    "dport": 8080,
                    "len": 100,
                    "time": "2021-01-01 00:00:00",
                },
                {
                    "id": 3,
                    "source": "wechat",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "proto": "TCP",
                    "sport": 80,
                    "dport": 8080,
                    "len": 100,
                    "time": "2021-01-01 00:00:00",
                },
            ]
            with open(analysed_json, "w", encoding="utf-8") as f:
                json.dump(flow, f)
        else:
            with open(analysed_json, "r", encoding="utf-8") as f:
                flow = json.load(f)
        source_dict = dict()
        for data in flow:
            if data["source"] not in source_dict:
                source_dict[data["source"]] = [1, [data]]
            else:
                source_dict[data["source"]][0] += 1
                source_dict[data["source"]][1].append(data)
        return render_template(
            "./DLVisibility/flow_analyse.html", data_flow=flow, source_dict=source_dict
        )


# result_analyse
@app.route("/result_analyse/", methods=["POST", "GET"])
def result_analyse():
    if NetType == None:
        flash("请先选择网络类型!")
        return redirect(url_for("select_method", next="result_analyse"))
    else:
        netFolder = app.config["NETWORK_FOLDER"]
        current_netFolder = os.path.join(netFolder, NetType)
        ACC_json = os.path.join(current_netFolder, "ACC结果分析.json")
        if not os.path.exists(current_netFolder):
            os.makedirs(current_netFolder)
        if not os.path.exists(ACC_json):
            ACC = [[0, 0], [1, 0.7], [2, 0.85], [3, 0.9], [6, 0.95]]
            with open(ACC_json, "w", encoding="utf-8") as f:
                json.dump(ACC, f)
        else:
            with open(ACC_json, "r", encoding="utf-8") as f:
                ACC = json.load(f)

        loss_json = os.path.join(current_netFolder, "loss结果分析.json")
        if not os.path.exists(loss_json):
            loss = [[0, 6], [1, 3], [2, 1.5], [6, 1]]
            with open(loss_json, "w", encoding="utf-8") as f:
                json.dump(loss, f)
        else:
            with open(loss_json, "r", encoding="utf-8") as f:
                loss = json.load(f)

        mixmatrix_json = os.path.join(current_netFolder, "混淆矩阵结果分析.json")
        if not os.path.exists(mixmatrix_json):
            mixmatrix = [[0, 0, 177], [0, 1, 3854], [1, 0, 5393], [1, 1, 76]]

            with open(mixmatrix_json, "w", encoding="utf-8") as f:
                json.dump(mixmatrix, f)
        else:
            with open(mixmatrix_json, "r", encoding="utf-8") as f:
                mixmatrix = json.load(f)
        nums = [mixmatrix[0][2], mixmatrix[1][2], mixmatrix[2][2], mixmatrix[3][2]]
        minn = min(nums)
        maxn = max(nums)
        return render_template(
            "./DLVisibility/result_analyse.html",
            ACC=ACC,
            loss=loss,
            mixmatrix=mixmatrix,
            min=minn,
            max=maxn,
        )


# select_method
@app.route("/select_method/", methods=["POST", "GET"])
def select_method():
    global route
    methods = {
        "cnn1d": {
            "name": "一维卷积神经网络",
            "description": "一维卷积神经网络（1D CNN）主要用于处理具有时间序列结构的数据，如语音信号、文本数据等。它通过卷积核在输入数据上滑动，提取局部的特征。",
        },
        "cnn2d": {
            "name": "二维卷积神经网络",
            "description": "二维卷积神经网络（2D CNN）广泛应用于图像处理领域，如图像分类、物体检测等。它能够在二维空间上提取图像的局部特征，并保持空间关系。",
        },
        "cnn_lstm": {
            "name": "长短期记忆卷积神经网络",
            "description": "长短期记忆卷积神经网络（CNN-LSTM）结合了卷积神经网络（CNN）和长短期记忆网络（LSTM）。CNN 用于提取局部特征，LSTM 用于处理时间序列数据。这种结构常用于视频处理和自然语言处理等任务。",
        },
    }
    type_value = request.form.get("type")
    if request.method == "GET":
        route = request.args.get("next")
        return render_template("./DLVisibility/select_method.html", methods=methods)
    elif request.method == "POST":
        global NetType
        if type_value == "cnn1d":
            flash("已选择一维卷积神经网络")
            NetType = "cnn1d"
            if route:
                return redirect(url_for(route))
        elif type_value == "cnn2d":
            flash("已选择二维卷积神经网络")
            NetType = "cnn2d"
            if route:
                return redirect(url_for(route))
        elif type_value == "cnn_lstm":
            flash("已选择长短期记忆卷积神经网络")
            NetType = "cnn_lstm"
            if route:
                return redirect(url_for(route))
        else:
            flash("请选择一个方法")
        return render_template("./DLVisibility/select_method.html", methods=methods)


# ----------------------------------------------数据提取页面---------------------------------------------

# Web数据


@app.route("/webdata/", methods=["POST", "GET"])
def webdata():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="webdata"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        webdata_list = web_data(PCAPS, host_ip)
        if dataid:
            return webdata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template("./dataextract/webdata.html", webdata=webdata_list)


# Mail数据


@app.route("/maildata/", methods=["POST", "GET"])
def maildata():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="maildata"))
    else:
        dataid = request.args.get("id")
        filename = request.args.get("filename")
        datatype = request.args.get("datatype")
        host_ip = get_host_ip(PCAPS)
        mailata_list = mail_data(PCAPS, host_ip)
        filepath = app.config["FILE_FOLDER"] + "Mail/"
        if datatype == "raw":
            raw_data = mailata_list[int(dataid) - 1]["data"]
            with open(filepath + "raw_data.txt", "w", encoding="UTF-8") as f:
                f.write(raw_data)
            return send_from_directory(filepath, "raw_data.txt", as_attachment=True)
        if filename and dataid:
            filename_ = (
                hashlib.md5(filename.encode("UTF-8")).hexdigest()
                + "."
                + filename.split(".")[-1]
            )
            attachs_dict = mailata_list[int(dataid) - 1]["parse_data"]["attachs_dict"]
            mode = "wb"
            encoding = None
            if isinstance(attachs_dict[filename], str):
                mode = "w"
                encoding = "UTF-8"
            elif isinstance(attachs_dict[filename], bytes):
                mode = "wb"
                encoding = None
            with open(filepath + filename_, mode, encoding=encoding) as f:
                f.write(attachs_dict[filename])
            return send_from_directory(filepath, filename_, as_attachment=True)
        if dataid:
            # return mailata_list[int(dataid)-1]['data'].replace('\r\n',
            # '<br>')
            maildata = mailata_list[int(dataid) - 1]["parse_data"]
            return render_template(
                "./dataextract/mailparsedata.html", maildata=maildata, dataid=dataid
            )
        else:
            return render_template("./dataextract/maildata.html", maildata=mailata_list)


# FTP数据
@app.route("/ftpdata/", methods=["POST", "GET"])
def ftpdata():
    if PCAPS == None:
        flash("请先上传要分析得数据包!")
        return redirect(url_for("upload", next="ftpdata"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        ftpdata_list = telnet_ftp_data(PCAPS, host_ip, 21)
        if dataid:
            return ftpdata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template("./dataextract/ftpdata.html", ftpdata=ftpdata_list)


# Telnet数据
@app.route("/telnetdata/", methods=["POST", "GET"])
def telnetdata():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="telnetdata"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        telnetdata_list = telnet_ftp_data(PCAPS, host_ip, 23)
        if dataid:
            return telnetdata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template(
                "./dataextract/telnetdata.html", telnetdata=telnetdata_list
            )


# 客户端信息
@app.route("/clientinfo/", methods=["POST", "GET"])
def clientinfo():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="clientinfo"))
    else:
        clientinfo_list = client_info(PCAPS)
        return render_template(
            "./dataextract/clientinfo.html", clientinfos=clientinfo_list
        )


# 敏感数据
@app.route("/sendata/", methods=["POST", "GET"])
def sendata():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="sendata"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        sendata_list = sen_data(PCAPS, host_ip)
        if dataid:
            return sendata_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
        else:
            return render_template("./dataextract/sendata.html", sendata=sendata_list)


# ----------------------------------------------一异常信息页面---------------------------------------------


# 异常数据
@app.route("/exceptinfo/", methods=["POST", "GET"])
def exceptinfo():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="exceptinfo"))
    else:
        dataid = request.args.get("id")
        host_ip = get_host_ip(PCAPS)
        warning_list = exception_warning(PCAPS, host_ip)
        if dataid:
            if warning_list[int(dataid) - 1]["data"]:
                return warning_list[int(dataid) - 1]["data"].replace("\r\n", "<br>")
            else:
                return "<center><h3>无相关数据包详情</h3></center>"
        else:
            return render_template("./exceptions/exception.html", warning=warning_list)


# ----------------------------------------------文件提取---------------------------------------------
# WEB文件提取


@app.route("/webfile/", methods=["POST", "GET"])
def webfile():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="webfile"))
    else:
        host_ip = get_host_ip(PCAPS)
        filepath = os.path.join(app.config["FILE_FOLDER"], "Web")
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        web_list = web_file(PCAPS, host_ip, filepath)
        file_dict = dict()
        for web in web_list:
            file_dict[os.path.split(web["filename"])[-1]] = web["filename"]
        file = request.args.get("file")
        if file in file_dict:
            filename = (
                hashlib.md5(file.encode("UTF-8")).hexdigest()
                + "."
                + file.split(".")[-1]
            )
            os.rename(filepath + file, filepath + filename)
            return send_from_directory(filepath, filename, as_attachment=True)
        else:
            return render_template("./fileextract/webfile.html", web_list=web_list)


# Mail文件提取


@app.route("/mailfile/", methods=["POST", "GET"])
def mailfile():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="mailfile"))
    else:
        host_ip = get_host_ip(PCAPS)
        filepath = os.path.join(app.config["FILE_FOLDER"], "Mail")
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        mail_list = mail_file(PCAPS, host_ip, filepath)
        file_dict = dict()
        for mail in mail_list:
            file_dict[os.path.split(mail["filename"])[-1]] = mail["filename"]
        file = request.args.get("file")
        if file in file_dict:
            filename = (
                hashlib.md5(file.encode("UTF-8")).hexdigest()
                + "."
                + file.split(".")[-1]
            )
            os.rename(filepath + file, filepath + filename)
            return send_from_directory(filepath, filename, as_attachment=True)
        else:
            return render_template("./fileextract/mailfile.html", mail_list=mail_list)


# FTP文件提取
@app.route("/ftpfile/", methods=["POST", "GET"])
def ftpfile():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="ftpfile"))
    else:
        host_ip = get_host_ip(PCAPS)
        filepath = os.path.join(app.config["FILE_FOLDER"], "FTP")
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        ftp_list = ftp_file(PCAPS, host_ip, filepath)
        file_dict = dict()
        for ftp in ftp_list:
            file_dict[os.path.split(ftp["filename"])[-1]] = ftp["filename"]
        file = request.args.get("file")
        if file in file_dict:
            filename = (
                hashlib.md5(file.encode("UTF-8")).hexdigest()
                + "."
                + file.split(".")[-1]
            )
            os.rename(filepath + file, filepath + filename)
            return send_from_directory(filepath, filename, as_attachment=True)
        else:
            return render_template("./fileextract/ftpfile.html", ftp_list=ftp_list)


# 所有二进制文件提取


@app.route("/allfile/", methods=["POST", "GET"])
def allfile():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for("upload", next="allfile"))
    else:
        filepath = os.path.join(app.config["FILE_FOLDER"], "All")
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        allfiles_dict = all_files(PCAPS, filepath)
        file = request.args.get("file")
        if file in allfiles_dict:
            filename = (
                hashlib.md5(file.encode("UTF-8")).hexdigest()
                + "."
                + file.split(".")[-1]
            )
            os.rename(filepath + file, filepath + filename)
            return send_from_directory(filepath, filename, as_attachment=True)
        else:
            return render_template(
                "./fileextract/allfile.html", allfiles_dict=allfiles_dict
            )


# ----------------------------------------------错误处理页面---------------------------------------------
@app.errorhandler(404)
def internal_error(error):
    return render_template("./error/404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("./error/500.html"), 500
