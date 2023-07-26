#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
import smtplib
import socket
from concurrent import futures
import time
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

main_host = ""
result = ""
mail_body = ""
overall_ok_flg = "OK"


JST = timezone(timedelta(hours=+9), "JST")

ar_host = {
    "server_name": "server_ip"
}

target_ip_accept_port = {
    #許可ポート
    "server_name": [25, 80, 443]
}

forbidden_port = [21, 22]

map_port_to_service = {
    22:"SSH",
    25:"MAIL",
    80:"HTTP",
    443:"HTTPS",
    4949:"MUNIN",
    5666:"NAGIOS",
    3000:"PPP",
    3001:"NESSUS",
    8443:"HTTPS-ALT"
}

#スキャン範囲設定
ar_port_list = list(range(0, 300))
ar_port_list.extend([21, 22, 25, 80, 443, 3306, 4949, 5666, 3000, 8443])
ar_port_list = list(dict.fromkeys(ar_port_list))

main_host = ""

ar_open_port = []
def scan_port(port):
    global main_host
    this_port_open = False
    connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    response_code = connect.connect_ex((main_host, port))
    connect.close()

    if (port/10)%10 == 0:
        #デバッグ用
        print("scanning:" + str(port))

    if response_code == 0:
        this_port_open = 1

    return [port, this_port_open]



def scan_host(host):
    global main_host
    global result

    host_ok_flg = "OK"
    main_host = ar_host[host]


    result += "[" + host + "]"

    ar_futures = {}
    print("port_scan init:" + host)
    start_time = time.perf_counter()
    with futures.ThreadPoolExecutor(max_workers=200) as executor:
        ar_futures = executor.map(scan_port, ar_port_list)

    end_time = time.perf_counter()

    scan_result = ""
    for future in ar_futures:
        if future[1] == 1:
            if (future[0] in target_ip_accept_port[host]) and (future[0] not in forbidden_port):
                scan_result += "{0}/TCP open {1}\n".format(future[0], map_port_to_service[future[0]])
            else:
                global overall_ok_flg
                overall_ok_flg = "NG"
                host_ok_flg = "NG"
                if (future[0] in forbidden_port):
                    scan_result += "{0}/TCP open {1}\n".format(future[0], map_port_to_service[future[0]])
                else:
                    scan_result += "{0}/TCP open UNKNOWN\n".format(future[0])

    result += " " + host_ok_flg + "\n"
    result += "Starting Python Port Scanner v0.1 at {}\n".format(datetime.now())
    result += "All 310 ports are scanned\n\n"
    result += "PORT STATE SERVICE\n"
    result += scan_result
    result += "\n"
    result += "Scan finished in {:.2f}\n".format(end_time-start_time)
    result += "--------------------\n"

for host in ar_host:
    scan_host(host)


mail_body += "[ポートスキャン結果] {}\n\n".format(overall_ok_flg)
mail_body += "[詳細]\n"
mail_body += result

mail_from = "xxx@xxxx.co.jp"
if overall_ok_flg == "OK":
    mail_to = "xxx@xxx.com"
else:
    mail_to = "xxx@xxx.com"

mail_body = mail_body

msg = MIMEText(mail_body, "plain", "utf-8")
msg["Subject"] = "[Port Scan Report] {0} Result:{1}".format(datetime.date(datetime.now()), overall_ok_flg)
msg["From"] = mail_from
msg["To"] = mail_to

with smtplib.SMTP("localhost") as smtp:
    smtp.send_message(msg)
    smtp.quit()