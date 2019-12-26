from ip2geotools.databases.noncommercial import DbIpCity
import os
import logging

__author__ = "AmirHossein Ashouripour"
"""definition
        Author: AmirHossein Ashouripour
        Date: 26/12/2019
        Description: This peace of code finds IP Addresses from log files and drop connection using Firewalld
"""
logging.basicConfig(level=logging.INFO)

MERGEDLOG = '/tmp/merged.log'
LOGTEMP = '/tmp/logtemp'
MAINADDRESS = '/opt/projects/erp/logs/nginx/'
BLACKLIST = 'black_ips'
IPSET = 'black_countries'


def get_ip_information(ip_address):
    response = DbIpCity.get(ip_address, api_key='free')
    return response


def set_iptables(blk_ips):
    black_ips = open(BLACKLIST, "w")
    for b_ip in blk_ips:
        black_ips.write("%s\n" % b_ip)
    black_ips.close()

    get = os.popen('firewall-cmd --permanent --get-ipsets')
    ip_sets = get.read()
    if BLACKLIST in ip_sets:
        add = os.popen('firewall-cmd --permanent --ipset=%s --add-entries-from-file=%s' % (IPSET, BLACKLIST))
        logging.info('add:' + add.read())
    else:
        new = os.popen('firewall-cmd --permanent --new-ipset=%s --type=hash:net' % IPSET)
        logging.info('new:' + new.read())

        if new.read() == 'success':
            ip_set = os.popen('firewall-cmd --permanent --ipset=%s --add-entries-from-file=%s' % (IPSET, BLACKLIST))
            logging.info('ip_set:' + ip_set.read())
            if ip_set.read() == 'success':
                reload = os.popen('firewall-cmd reload')
                logging.info('reload:' + reload.read())
                if reload.read() =='success':

                    os.popen('rm -f %s' % MERGEDLOG)
        else:
            logging.error('new:' + new.read())


def find_ips(file_address):
    ip_array = []
    with open(file_address) as fileObject:
        for line in fileObject:
            line_array = line.split(' ')
            if 'client:' in line_array:
                threat = line_array[line_array.index('client:') + 1].replace(',', '')
                ip_array.append(threat)
    return ip_array


def controller(address):
    log_manager(address)
    ip_array = find_ips(LOGTEMP)
    blacklist = check_country(refine(ip_array))
    # set_iptables(blacklist)


def refine(ips):
    return list(set(ips))


def check_country(ips):
    blk_ips = []
    for x in ips:
        ip_info = get_ip_information(x)
        blk_ips.append(x) if (ip_info.country != 'IR') else print(x + ' from ' + ip_info.city)
        print(x + ' from Country: ' + ip_info.country + ' city: ' + ip_info.city)
    return blk_ips


def log_manager(address):
    get_old_logs_number = get_old_lines_number()
    get_log_files = os.popen('ls ' + address)
    logs = get_log_files.read().split('\n')
    file_lines = {}
    for x in range(len(logs)):
        if len(logs[x]) > 0:
            file_lines[logs[x]] = get_line_count(address, logs[x])
            if len(get_old_logs_number) <1:
                os.popen('cat %s >> %s' % (address + logs[x], MERGEDLOG))
            else:
                os.popen('tail --lines=+%s %s >> %s' % (
                    get_old_logs_number.get(logs[x]) if (int(get_old_logs_number.get(logs[x])) > 0) else 1,
                    address + logs[x], MERGEDLOG))

        print(file_lines)


def get_old_lines_number():
    logs = {}
    line_saize=os.popen('wc -l %s' % LOGTEMP).read().split(' ')[0]

    logging.info('count of lines inlogtemp is:' + line_saize)

    if line_saize in locals() and line_saize != 0:
        print('count of lines in logtemp is:'+line_saize)
        with open(LOGTEMP) as tmp_file:

            print('in the opener:' + line_saize)
            for line in tmp_file:
                log = line.split(':')
                print(log[0] + ' ' + log[1])
                logs[log[0]] = log[1]

    return logs


def get_line_count(address, log):
    wc = os.popen('wc -l %s' % address + log)
    tmp_file = open(LOGTEMP, "w")
    tmp_file.write("%s: %s\n" % (log, wc.read()))
    tmp_file.close()

    return wc


if __name__ == '__main__':

    controller(MAINADDRESS)
