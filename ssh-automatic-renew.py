# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# Simon Fu
# www.fushupeng.com
# contact@fushupeng.com
# Life is short, and world is wide.
import datetime
import json
import socket
import time
import paramiko as paramiko
import configparser
from vultr import Vultr


def server_check():
    global config
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(1)
    try:
        sk.connect((config.get('server', 'domain'), int(config.get('server', 'port'))))
        res = True
    except Exception as e:
        print(e)
        res = False
    sk.close()
    return res


def renew_server():
    global config
    result = True
    api_key = config.get('vultr', 'api-key')
    vultr = Vultr(api_key)
    current_ids = []
    try:
        current_servers = vultr.server.list()
        for server_id in current_servers:
            current_ids.append(server_id)

        res = vultr.server.create(5, 201, 167)
        vps_id = res['SUBID']
        vps_ip = vps_password = ''
        times = 0
        msg = '获取成功'
        vps_detail = vultr.server.list(vps_id)
        status = vps_detail['status']
        pw_status = vps_detail['power_status']
        while status != 'active' or pw_status != 'running':
            times += 1
            print('正在进行第 ' + str(times) + ' 尝试获取服务器信息')
            vps_detail = vultr.server.list(vps_id)
            status = vps_detail['status']
            pw_status = vps_detail['power_status']
            vps_ip = vps_detail['main_ip']
            vps_password = vps_detail['default_password']
            if times > 100:
                msg = '获取失败，获取次数超过次数限制'
                result = False
                break
            time.sleep(1)
        return {
            'result': result,
            'ip': vps_ip,
            'username': 'root',
            'password': vps_password,
            'delete_servers': current_ids,
            'msg': msg
        }
    except Exception:
        return {'result': False, 'msg': '创建服务器或获取服务器信息失败'}


def server_configuration(server):
    print('服务器创建成功，服务器信息如下: %s' % json.dumps(server))
    now = datetime.datetime.now()
    for i in range(0, 60):
        print("%s 秒后尝试链接服务器" % (60 - i))
        time.sleep(1)

    paramiko.util.log_to_file("./%s-%s-ssh.log" % (now.strftime('%Y-%m-%d'), server['ip']))

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server['ip'], username=server['username'], password=server['password'])
    print('开始安装系统环境')

    print('准备安装 supervisor、pip、shadowsocks')
    stdin, stdout, stderr = ssh.exec_command(
        'yum -y install supervisor net-tools && curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && '
        'sudo python get-pip.py && pip install shadowsocks && mkdir -p /etc/supervisord.d/'
    )
    stdout.read()
    stdin, stdout, stderr = ssh.exec_command('systemctl enable supervisord')
    stdout.read()
    print('安装完成，准备上传所需文件')

    # 开始上传功能
    t = paramiko.Transport((server['ip'], 22))
    t.connect(username=server['username'], password=server['password'])
    sftp = paramiko.SFTPClient.from_transport(t)
    print('准备上传bbr.sh')
    remote_path = '/root/bbr.sh'
    local_path = './bbr.sh'
    sftp.put(local_path, remote_path)

    print('准备上传ssserver.ini')
    remote_path = '/etc/supervisord.d/ssserver.ini'
    local_path = './ssserver.ini'
    sftp.put(local_path, remote_path)
    print('准备上传shadowsocks.json')
    remote_path = '/etc/shadowsocks.json'
    local_path = './shadowsocks.json'
    sftp.put(local_path, remote_path)
    t.close()
    print('文件上传完成，开始安装bbr')

    ssh.exec_command('chmod 755 /root/bbr.sh')
    stdin, stdout, stderr = ssh.exec_command('/root/bbr.sh')
    stdout.read()
    ssh.close()
    print('安装BBR完成，系统重启中')
    for i in range(0, 60):
        print("%s 秒后重新链接服务器" % (60 - i))
        time.sleep(1)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server['ip'], username=server['username'], password=server['password'])
    stdin, stdout, stderr = ssh.exec_command('netstat -nlt | grep 10704')
    out = stdout.read()
    ssh.close()
    if len(str(out, encoding="utf-8")) > 0:
        return True
    else:
        return False


def destroy_servers(server_ids):
    print('开始删除原有的服务器')
    global config
    api_key = config.get('vultr', 'api-key')
    vultr = Vultr(api_key)
    for id in server_ids:
        vultr.server.destroy(id)


def change_domain():
    pass


def main():
    global config
    if server_check():
        print("服务器链接正常============================")
    else:
        print("服务器链接失败，准备重新创建服务器============================")
        # 1、创建新的服务器
        new_server = renew_server()
        if not new_server['result']:
            print(new_server['msg'])
            exit(0)
        # 2、配置新的服务器
        if not server_configuration(new_server):
            print('服务器配置失败，请登录服务器进行查看')
            exit(0)
        print('服务器配置成功，服务器地址: %s, ssh端口：10704' % new_server['ip'])
        # 3、关闭旧的服务器
        destroy_servers(new_server['delete_servers'])
        # 4、解析调整
        if config.get('aliyun', 'access-key-id') != '' and config.get('aliyun', 'access-key-id') != '':
            print('开始配置阿里云域名解析')
            change_domain()
        else:
            config.set('server', 'domain', new_server['ip'])
            # 保存 config 文件
            try:
                with open("datatype.conf", "w+") as f:
                    config.write(f)
            except ImportError:
                pass
            print('阿里云信息未配置，退出')


if __name__ == "__main__":
    config = configparser.ConfigParser(allow_no_value=False)
    config.read("config.cfg")
    if config.get('vultr', 'api-key') == '':
        print('请提供 Vultr API-KEY')
        exit(0)
    main()

