# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# Simon Fu
# www.fushupeng.com
# contact@fushupeng.com
# Life is short, and world is wide.
import socket
import time
import paramiko as paramiko
from vultr import Vultr


def server_check():
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(1)
    try:
        sk.connect((config['server'], config['port']))
        res = True
    except Exception:
        res = False
    sk.close()
    return res


def renew_server():
    result = True
    api_key = config['vultr-api-key']
    vultr = Vultr(api_key)
    try:
        # DCID: {"6": {"DCID": "6", "name": "Atlanta", "country": "US", "continent": "North America", "state": "GA", "ddos_protection": false, "block_storage": false, "regioncode": "ATL"}, "2": {"DCID": "2", "name": "Chicago", "country": "US", "continent": "North America", "state": "IL", "ddos_protection": true, "block_storage": false, "regioncode": "ORD"}, "3": {"DCID": "3", "name": "Dallas", "country": "US", "continent": "North America", "state": "TX", "ddos_protection": true, "block_storage": false, "regioncode": "DFW"}, "5": {"DCID": "5", "name": "Los Angeles", "country": "US", "continent": "North America", "state": "CA", "ddos_protection": true, "block_storage": false, "regioncode": "LAX"}, "39": {"DCID": "39", "name": "Miami", "country": "US", "continent": "North America", "state": "FL", "ddos_protection": true, "block_storage": false, "regioncode": "MIA"}, "1": {"DCID": "1", "name": "New Jersey", "country": "US", "continent": "North America", "state": "NJ", "ddos_protection": true, "block_storage": true, "regioncode": "EWR"}, "4": {"DCID": "4", "name": "Seattle", "country": "US", "continent": "North America", "state": "WA", "ddos_protection": true, "block_storage": false, "regioncode": "SEA"}, "12": {"DCID": "12", "name": "Silicon Valley", "country": "US", "continent": "North America", "state": "CA", "ddos_protection": true, "block_storage": false, "regioncode": "SJC"}, "40": {"DCID": "40", "name": "Singapore", "country": "SG", "continent": "Asia", "state": "", "ddos_protection": false, "block_storage": false, "regioncode": "SGP"}, "7": {"DCID": "7", "name": "Amsterdam", "country": "NL", "continent": "Europe", "state": "", "ddos_protection": true, "block_storage": false, "regioncode": "AMS"}, "25": {"DCID": "25", "name": "Tokyo", "country": "JP", "continent": "Asia", "state": "", "ddos_protection": false, "block_storage": false, "regioncode": "NRT"}, "8": {"DCID": "8", "name": "London", "country": "GB", "continent": "Europe", "state": "", "ddos_protection": true, "block_storage": false, "regioncode": "LHR"}, "24": {"DCID": "24", "name": "Paris", "country": "FR", "continent": "Europe", "state": "", "ddos_protection": true, "block_storage": false, "regioncode": "CDG"}, "9": {"DCID": "9", "name": "Frankfurt", "country": "DE", "continent": "Europe", "state": "", "ddos_protection": true, "block_storage": false, "regioncode": "FRA"}, "22": {"DCID": "22", "name": "Toronto", "country": "CA", "continent": "North America", "state": "", "ddos_protection": false, "block_storage": false, "regioncode": "YTO"}, "19": {"DCID": "19", "name": "Sydney", "country": "AU", "continent": "Australia", "state": "", "ddos_protection": false, "block_storage": false, "regioncode": "SYD"}}
        # Los Angeles - 5
        # Plan ID:{"201": {"VPSPLANID": "201", "name": "1024 MB RAM,25 GB SSD,1.00 TB BW", "vcpu_count": "1", "ram": "1024", "disk": "25", "bandwidth": "1.00", "bandwidth_gb": "1024", "price_per_month": "5.00", "plan_type": "SSD", "windows": false, "available_locations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 19, 22, 24, 25, 39, 40]}, "202": {"VPSPLANID": "202", "name": "2048 MB RAM,55 GB SSD,2.00 TB BW", "vcpu_count": "1", "ram": "2048", "disk": "55", "bandwidth": "2.00", "bandwidth_gb": "2048", "price_per_month": "10.00", "plan_type": "SSD", "windows": false, "available_locations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 19, 22, 24, 25, 39, 40]}, "203": {"VPSPLANID": "203", "name": "4096 MB RAM,80 GB SSD,3.00 TB BW", "vcpu_count": "2", "ram": "4096", "disk": "80", "bandwidth": "3.00", "bandwidth_gb": "3072", "price_per_month": "20.00", "plan_type": "SSD", "windows": false, "available_locations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 19, 22, 24, 25, 39, 40]}, "204": {"VPSPLANID": "204", "name": "8192 MB RAM,160 GB SSD,4.00 TB BW", "vcpu_count": "4", "ram": "8192", "disk": "160", "bandwidth": "4.00", "bandwidth_gb": "4096", "price_per_month": "40.00", "plan_type": "SSD", "windows": false, "available_locations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 19, 22, 25, 39, 40]}, "205": {"VPSPLANID": "205", "name": "16384 MB RAM,320 GB SSD,5.00 TB BW", "vcpu_count": "6", "ram": "16384", "disk": "320", "bandwidth": "5.00", "bandwidth_gb": "5120", "price_per_month": "80.00", "plan_type": "SSD", "windows": false, "available_locations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 19, 22, 25, 39, 40]}, "206": {"VPSPLANID": "206", "name": "32768 MB RAM,640 GB SSD,6.00 TB BW", "vcpu_count": "8", "ram": "32768", "disk": "640", "bandwidth": "6.00", "bandwidth_gb": "6144", "price_per_month": "160.00", "plan_type": "SSD", "windows": false, "available_locations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 19, 22, 25, 39, 40]}, "207": {"VPSPLANID": "207", "name": "65536 MB RAM,1280 GB SSD,10.00 TB BW", "vcpu_count": "16", "ram": "65536", "disk": "1280", "bandwidth": "10.00", "bandwidth_gb": "10240", "price_per_month": "320.00", "plan_type": "SSD", "windows": false, "available_locations": [2, 3, 5, 6, 25, 40]}, "208": {"VPSPLANID": "208", "name": "98304 MB RAM,1600 GB SSD,15.00 TB BW", "vcpu_count": "24", "ram": "98304", "disk": "1600", "bandwidth": "15.00", "bandwidth_gb": "15360", "price_per_month": "640.00", "plan_type": "SSD", "windows": false, "available_locations": []}, "115": {"VPSPLANID": "115", "name": "8192 MB RAM,110 GB SSD,10.00 TB BW", "vcpu_count": "2", "ram": "8192", "disk": "110", "bandwidth": "10.00", "bandwidth_gb": "10240", "price_per_month": "60.00", "plan_type": "DEDICATED", "windows": false, "available_locations": [1, 2, 12, 25]}, "116": {"VPSPLANID": "116", "name": "16384 MB RAM,2x110 GB SSD,20.00 TB BW", "vcpu_count": "4", "ram": "16384", "disk": "110", "bandwidth": "20.00", "bandwidth_gb": "20480", "price_per_month": "120.00", "plan_type": "DEDICATED", "windows": false, "available_locations": [1, 2, 12]}, "117": {"VPSPLANID": "117", "name": "24576 MB RAM,3x110 GB SSD,30.00 TB BW", "vcpu_count": "6", "ram": "24576", "disk": "110", "bandwidth": "30.00", "bandwidth_gb": "30720", "price_per_month": "180.00", "plan_type": "DEDICATED", "windows": false, "available_locations": [1, 2, 12]}, "118": {"VPSPLANID": "118", "name": "32768 MB RAM,4x110 GB SSD,40.00 TB BW", "vcpu_count": "8", "ram": "32768", "disk": "110", "bandwidth": "40.00", "bandwidth_gb": "40960", "price_per_month": "240.00", "plan_type": "DEDICATED", "windows": false, "available_locations": [2, 12]}, "400": {"VPSPLANID": "400", "name": "1024 MB RAM,32 GB SSD,1.00 TB BW", "vcpu_count": "1", "ram": "1024", "disk": "32", "bandwidth": "1.00", "bandwidth_gb": "1024", "price_per_month": "6.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [1, 2, 6, 12]}, "401": {"VPSPLANID": "401", "name": "2048 MB RAM,64 GB SSD,2.00 TB BW", "vcpu_count": "1", "ram": "2048", "disk": "64", "bandwidth": "2.00", "bandwidth_gb": "2048", "price_per_month": "12.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [1, 2, 6, 12]}, "402": {"VPSPLANID": "402", "name": "4096 MB RAM,128 GB SSD,3.00 TB BW", "vcpu_count": "2", "ram": "4096", "disk": "128", "bandwidth": "3.00", "bandwidth_gb": "3072", "price_per_month": "24.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [1, 2, 6, 12]}, "403": {"VPSPLANID": "403", "name": "8192 MB RAM,256 GB SSD,4.00 TB BW", "vcpu_count": "3", "ram": "8192", "disk": "256", "bandwidth": "4.00", "bandwidth_gb": "4096", "price_per_month": "48.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [1, 2, 6, 12]}, "404": {"VPSPLANID": "404", "name": "16384 MB RAM,384 GB SSD,5.00 TB BW", "vcpu_count": "4", "ram": "16384", "disk": "384", "bandwidth": "5.00", "bandwidth_gb": "5120", "price_per_month": "96.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [1, 2, 6, 12]}, "405": {"VPSPLANID": "405", "name": "32768 MB RAM,512 GB SSD,6.00 TB BW", "vcpu_count": "8", "ram": "32768", "disk": "512", "bandwidth": "6.00", "bandwidth_gb": "6144", "price_per_month": "192.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [1, 2, 6, 12]}, "406": {"VPSPLANID": "406", "name": "49152 MB RAM,768 GB SSD,8.00 TB BW", "vcpu_count": "12", "ram": "49152", "disk": "768", "bandwidth": "8.00", "bandwidth_gb": "8192", "price_per_month": "256.00", "plan_type": "HIGHFREQUENCY", "windows": false, "available_locations": [2, 6, 12]}}
        # 1024 MB RAM,25 GB SSD,1.00 TB BW - 201
        # OSID: {"127": {"OSID": 127, "name": "CentOS 6 x64", "arch": "x64", "family": "centos", "windows": false}, "147": {"OSID": 147, "name": "CentOS 6 i386", "arch": "i386", "family": "centos", "windows": false}, "167": {"OSID": 167, "name": "CentOS 7 x64", "arch": "x64", "family": "centos", "windows": false}, "215": {"OSID": 215, "name": "Ubuntu 16.04 x64", "arch": "x64", "family": "ubuntu", "windows": false}, "216": {"OSID": 216, "name": "Ubuntu 16.04 i386", "arch": "i386", "family": "ubuntu", "windows": false}, "270": {"OSID": 270, "name": "Ubuntu 18.04 x64", "arch": "x64", "family": "ubuntu", "windows": false}, "302": {"OSID": 302, "name": "Ubuntu 18.10 x64", "arch": "x64", "family": "ubuntu", "windows": false}, "338": {"OSID": 338, "name": "Ubuntu 19.04 x64", "arch": "x64", "family": "ubuntu", "windows": false}, "193": {"OSID": 193, "name": "Debian 8 x64 (jessie)", "arch": "x64", "family": "debian", "windows": false}, "194": {"OSID": 194, "name": "Debian 8 i386 (jessie)", "arch": "i386", "family": "debian", "windows": false}, "244": {"OSID": 244, "name": "Debian 9 x64 (stretch)", "arch": "x64", "family": "debian", "windows": false}, "230": {"OSID": 230, "name": "FreeBSD 11 x64", "arch": "x64", "family": "freebsd", "windows": false}, "327": {"OSID": 327, "name": "FreeBSD 12 x64", "arch": "x64", "family": "freebsd", "windows": false}, "324": {"OSID": 324, "name": "OpenBSD 6.4 x64", "arch": "x64", "family": "openbsd", "windows": false}, "341": {"OSID": 341, "name": "OpenBSD 6.5 x64", "arch": "x64", "family": "openbsd", "windows": false}, "179": {"OSID": 179, "name": "CoreOS Stable", "arch": "x64", "family": "coreos", "windows": false}, "322": {"OSID": 322, "name": "Fedora 29 x64", "arch": "x64", "family": "fedora", "windows": false}, "342": {"OSID": 342, "name": "Fedora 30 x64", "arch": "x64", "family": "fedora", "windows": false}, "124": {"OSID": 124, "name": "Windows 2012 R2 x64", "arch": "x64", "family": "windows", "windows": true}, "240": {"OSID": 240, "name": "Windows 2016 x64", "arch": "x64", "family": "windows", "windows": true}, "159": {"OSID": 159, "name": "Custom", "arch": "x64", "family": "iso", "windows": false}, "164": {"OSID": 164, "name": "Snapshot", "arch": "x64", "family": "snapshot", "windows": false}, "180": {"OSID": 180, "name": "Backup", "arch": "x64", "family": "backup", "windows": false}, "186": {"OSID": 186, "name": "Application", "arch": "x64", "family": "application", "windows": false}}
        # CentOS 7 x64 - 167
        res = vultr.server.create(5, 201, 167)
        vps_id = res['SUBID']
        vps_detail = vultr.server.list(vps_id)
        vps_ip = vps_detail['main_ip']
        vps_password = vps_detail['default_password']
        vps_created_time = vps_detail['date_created']
        times = 0
        msg = '获取成功'
        while vps_ip == '0.0.0.0' or vps_password == '' or vps_created_time == '':
            times += 1
            print('正在进行第 ' + str(times) + ' 尝试获取服务器信息')
            vps_detail = vultr.server.list(vps_id)
            print(vps_detail)
            vps_ip = vps_detail['main_ip']
            vps_password = vps_detail['default_password']
            vps_created_time = vps_detail['date_created']
            if times > 50:
                msg = '获取失败，获取次数超过次数限制'
                result = False
                break
            time.sleep(1)
        return {'result': result, 'ip': vps_ip, 'password': vps_password, 'create_time': vps_created_time, 'msg': msg}
    except Exception:
        return {'result': False, 'msg': '创建服务器或获取服务器信息失败'}


def server_configuration(ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)


def change_domain():
    pass


def main():
    if server_check():
        print("服务器链接正常============================")
    else:
        print("服务器链接失败，准备重新创建服务器============================")

        # 1、创建新的服务器
        new_server = renew_server()
        if not new_server['res']:
            print(new_server['msg'])
            exit(0)
        # 2、在新的服务器上进行配置基础信息，并重启
        # 3、关闭旧的服务器
        # 4、解析调整


if __name__ == "__main__":
    global config
    config = {
        'server': '',
        'port': 10704,
        'aliyun-access-key-id': 'LTAI4fDTYrKtHf6U',
        'aliyun-access-key-secret': 'osEia99g9MI1sVikA73N4bjVWmsW50',
        'vultr-api-key': 'BWSXRX53YWGFOAED5ZMQEG6MSQDGI5QK6IYQ',
    }
    main()
