from pyzabbix.api import ZabbixAPI, ZabbixAPIException
import logging
import yaml


conf_path = 'conf.yaml'


def get_config(conf_path=conf_path):
    with open(conf_path, 'r') as file:
        conf = yaml.load(file, Loader=yaml.FullLoader)
    return conf

def get_logger(logger_conf):
    log_file = logger_conf['log_dir'] + logger_conf['log_file']
    logger = logging.getLogger(__name__)
    fh = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    log_level = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR
    }
    logger.setLevel(log_level[logger_conf['log_level']])
    return logger


zapi = ZabbixAPI(url='http://192.168.1.104', user='Admin', password='zabbix')


def get_hosts(hosts_path):
    """
    Открывает hosts файл в режиме чтения
    разбивает весь файл на группы
    формирует и отдает dict в котором
    ключ первого уровня это группа, дальше хост, дальше информация по хосту
    """
    logger.debug(f'Get hosts. Hosts path: {hosts_path}')
    hosts_res = {}
    with open(hosts_path, 'r') as f:
        hosts_raw = f.read()

    hosts_groups_tmp = hosts_raw.split('[')
    hosts_groups = list(filter(None, hosts_groups_tmp))

    for hosts_group in hosts_groups:
        group, hosts = hosts_group.split(']')
        hosts_res[group] = {}
        hosts_list = list(filter(None, hosts.split('\n')))
        for host in hosts_list:
            host_name, host_ip = host.split()
            # добавь сюда проверку на дубликаты
            hosts_res[group][host_name] = {}
            hosts_res[group][host_name]['ip'] = host_ip.replace('ansible_host=', '')
    return hosts_res


def sync_zbx_groups():
    # добавь фильтрацию
    result3 = zapi.do_request('hostgroup.get', {})
    zbx_all_groups = {}
    for result in result3['result']:
        zbx_all_groups[result['name']] = result['groupid']

    zbx_groups = {}
    for hosts_group in hosts_res.keys():
        if hosts_group not in zbx_all_groups.keys():
            res = zapi.do_request('hostgroup.create', {"name": hosts_group})
            zbx_groups[hosts_group] = res['result']['groupids'][0]
        else:
            zbx_groups[hosts_group] = zbx_all_groups[hosts_group]
    return zbx_groups


def sync_zbx_hosts(hosts_res, zbx_groups):
    for group, hosts in hosts_res.items():
        # добавь фильтрацию
        hosts_zbx_group_tmp = zapi.do_request('host.get', {"groupids": zbx_groups[group]})['result']
        hosts_zbx_group = {}
        for zbx_group_result in hosts_zbx_group_tmp:
            # print(zbx_group_result)
            hosts_zbx_group[zbx_group_result['host']] = {}
            hosts_zbx_group[zbx_group_result['host']]['host'] = zbx_group_result['host']
            hosts_zbx_group[zbx_group_result['host']]['hostid'] = zbx_group_result['hostid']
        for host, host_info in hosts.items():
            if host not in hosts_zbx_group.keys():
                res_create_host = zapi.do_request('host.create', {
                                                    "host": host,
                                                    "interfaces": [
                                                        {
                                                            "type": 1,
                                                            "main": 1,
                                                            "useip": 1,
                                                            "ip": host_info['ip'],
                                                            "dns": "",
                                                            "port": "10050"
                                                        }
                                                    ],
                                                    "groups": [
                                                        {
                                                            "groupid": zbx_groups[group]
                                                        }
                                                    ],
                                                    "templates": [
                                                        {
                                                            "templateid": "10001"
                                                        }
                                                    ]
                                                })
                hosts_zbx_group[host] = {}
                hosts_zbx_group[host]['host'] = host
                hosts_zbx_group[host]['hostid'] = res_create_host['result']['hostids'][0]
                hosts_res[group][host]['hostid'] = hosts_zbx_group[host]['hostid']
            else:
                hosts_res[group][host]['hostid'] = hosts_zbx_group[host]['hostid']
    return hosts_res


def sync_proxy(sync_hosts):
    proxy_name_templ = 'zabbix-proxy-'
    sync_proxies_names = [proxy_name_templ + proxy_name for proxy_name in sync_hosts.keys()]
    zbx_proxies_tmp = zapi.do_request('proxy.get', {'filter': {'host': sync_proxies_names}, })
    zbx_proxies = {}
    for zbx_proxy in zbx_proxies_tmp['result']:
        zbx_proxies[zbx_proxy['host']] = zbx_proxy['proxyid']

    for proxy_name, hosts in sync_hosts.items():
        host_ids = [host_info['hostid'] for host_info in hosts.values()]
        tmp_ip_for_proxy = hosts[list(hosts.keys())[0]]['ip']
        proxy_ip = tmp_ip_for_proxy.split('.')
        proxy_ip[-1] = '1'
        proxy_ip = '.'.join(proxy_ip)
        print(proxy_ip)


        if proxy_name_templ + proxy_name not in zbx_proxies.keys():
            zapi.do_request('proxy.create',{
                "host": proxy_name_templ + proxy_name,
                "status": "6",
                "interface": {
                    "ip": proxy_ip,
                    "dns": "",
                    "useip": "1",
                    "port": "10051"
                     },
                     "hosts": host_ids})
        else:
            # print(proxy_name_templ + proxy_name)
            zapi.do_request('proxy.update', {
                            "proxyid": zbx_proxies[proxy_name_templ + proxy_name],
                            "hosts": host_ids})



# print(hosts_res)
# print(zbx_groups)
# print(sync_hosts)
# print(sync_proxy)
if __name__=='__main__':
    conf = get_config(conf_path)
    logger = get_logger(conf['logger'])
    logger.info('START')
    hosts_res = get_hosts(conf['hosts_file_path'])
    zbx_groups = sync_zbx_groups()
    sync_hosts = sync_zbx_hosts(hosts_res, zbx_groups)
    print(sync_hosts)
    sync_proxy = sync_proxy(sync_hosts)