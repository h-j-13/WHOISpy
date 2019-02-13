#!/usr/bin/env python
# encoding:utf-8

"""
域名WHOIS数据关键信息解析

为了更好地存储数据,在提取了WHOIS关键信息之后,还可以

- 将时间字符串进行标准化
- 将域名状态进行标准化

域名状态相关参考资料:
https://tools.ietf.org/html/rfc2832
https://www.songhaoyun.com/info/18109.html
https://www.ymw.cn/news/viewnews-1641.html
https://baike.baidu.com/item/%E5%9F%9F%E5%90%8D%E7%8A%B6%E6%80%81/9345763?fr=aladdin

如何通过函数名称(字符串)来优雅的调用函数?
https://stackoverflow.com/questions/3061/calling-a-function-of-a-module-by-using-its-name-a-string
"""

import re
import copy

import WHOIS_parser
from WHOIS_connect import WHOIS_srv_connect

ABLE_FORMAT_TIME = True
try:
    import pytz
    from dateutil.parser import parse
except ImportError:
    ABLE_FORMAT_TIME = False

CHOSE_WHOIS_server = WHOIS_parser.WHOIS_info_extract_func()

WHOIS_RECORD = {
    "domain": "",  # 域名
    "tld": "",  # 顶级域
    "flag": "",  # 状态标记
    "domain_status": "",  # 域名状态
    "sponsoring_registrar": "",  # 注册商
    "top_whois_server": "",  # 顶级域名服务器
    "sec_whois_server": "",  # 二级域名服务器
    "reg_name": "",  # 注册姓名
    "reg_phone": "",  # 注册电话
    "reg_email": "",  # 注册email
    "org_name": "",  # 注册公司名称
    "creation_date": "",  # 创建时间
    "expiration_date": "",  # 到期时间
    "updated_date": "",  # 更新时间
    "details": "",  # 原始信息(一级WHOIS信息 + 二级WHOIS信息)
    "top_whois_detail": "",  # 一级WHOIS信息
    "sec_whois_detail": "",  # 二级WHOIS信息
    "name_server": "",  # 域名服务器
}

# WHOIS 数据标记位
FLAG_CANT_DEAL = 0  # 不能处理
FLAG_OK = 1  # 正常
FLAG_NO_WHOIS_ADDR = -1  # 未找到WHOIS服务器
FLAG_TOP_WHOIS_FAILED = -2  # 一级WHOIS获取错误
FLAG_NO_SEC_WHOI_ADDR = -3  # 未找到二级WHOIS服务器
FLAG_SEC_WHOIS_FAILED = -4  # 二级WHOIS获取错误
FLAG_EMPTY_WHOIS_INFO = -5  # WHOIS信息为空
FLAG_INFO_EXTRACT_FAILED = -6  # WHOIS关键信息解析失败

# 状态值字典
WHOIS_STATUS_DICT = {
    # EPP
    "ADDPERIOD": "1",
    "AUTORENEWPERIOD": "2",
    "INACTIVE": "3",
    "OK": "4",
    "PENDINGCREATE": "5",
    "PENDINGDELETE": "6",
    "PENDINGRENEW": "7",
    "PENDINGRESTORE": "8",
    "PENDINGTRANSFER": "9",
    "PENDINGUPDATE": "10",
    "REDEMPTIONPERIOD": "11",
    "RENEWPERIOD": "12",
    "SERVERDELETEPROHIBITED": "13",
    "SERVERHOLD": "14",
    "SERVERRENEWPROHIBITED": "15",
    "SERVERTRANSFERPROHIBITED": "16",
    "SERVERUPDATEPROHIBITED": "17",
    "TRANSFERPERIOD": "18",
    "CLIENTDELETEPROHIBITED": "19",
    "CLIENTHOLD": "20",
    "CLIENTRENEWPROHIBITED": "21",
    "CLIENTTRANSFERPROHIBITED": "22",
    "CLIENTUPDATEPROHIBITED": "23",
    # RRP
    "ACTIVE": "24",
    "REGISTRYLOCK": "25",
    "REGISTRARLOCK": "26",
    "REGISTRYHOLD": "27",
    "REGISTRARHOLD": "28",
    # "REDEMPTIONPERIOD": "29", 重复
    # "PENDINGRESTORE": "30", 重复
    # "PENDINGDELETE": "31", 重复
    "NOTEXIST": "29",  # 域名不存在
    "NOSTATUS": "30",  # 无状态值
    "CONNECT": "31",  # de服务器状态
}


def format_timestamp(str_time):
    """将时间字符串进行标准化处理"""

    utc_timezone = pytz.utc
    timezone_info = {
        "A": 1 * 3600,
        "ACDT": 10.5 * 3600,
        "ACST": 9.5 * 3600,
        "ACT": -5 * 3600,
        "ACWST": 8.75 * 3600,
        "ADT": 4 * 3600,
        "AEDT": 11 * 3600,
        "AEST": 10 * 3600,
        "AET": 10 * 3600,
        "AFT": 4.5 * 3600,
        "AKDT": -8 * 3600,
        "AKST": -9 * 3600,
        "ALMT": 6 * 3600,
        "AMST": -3 * 3600,
        "AMT": -4 * 3600,
        "ANAST": 12 * 3600,
        "ANAT": 12 * 3600,
        "AQTT": 5 * 3600,
        "ART": -3 * 3600,
        "AST": 3 * 3600,
        "AT": -4 * 3600,
        "AWDT": 9 * 3600,
        "AWST": 8 * 3600,
        "AZOST": 0 * 3600,
        "AZOT": -1 * 3600,
        "AZST": 5 * 3600,
        "AZT": 4 * 3600,
        "AoE": -12 * 3600,
        "B": 2 * 3600,
        "BNT": 8 * 3600,
        "BOT": -4 * 3600,
        "BRST": -2 * 3600,
        "BRT": -3 * 3600,
        "BST": 6 * 3600,
        "BTT": 6 * 3600,
        "C": 3 * 3600,
        "CAST": 8 * 3600,
        "CAT": 2 * 3600,
        "CCT": 6.5 * 3600,
        "CDT": -5 * 3600,
        "CEST": 2 * 3600,
        "CET": 1 * 3600,
        "CHADT": 13.75 * 3600,
        "CHAST": 12.75 * 3600,
        "CHOST": 9 * 3600,
        "CHOT": 8 * 3600,
        "CHUT": 10 * 3600,
        "CIDST": -4 * 3600,
        "CIST": -5 * 3600,
        "CKT": -10 * 3600,
        "CLST": -3 * 3600,
        "CLT": -4 * 3600,
        "COT": -5 * 3600,
        "CST": -6 * 3600,
        "CT": -6 * 3600,
        "CVT": -1 * 3600,
        "CXT": 7 * 3600,
        "ChST": 10 * 3600,
        "D": 4 * 3600,
        "DAVT": 7 * 3600,
        "DDUT": 10 * 3600,
        "E": 5 * 3600,
        "EASST": -5 * 3600,
        "EAST": -6 * 3600,
        "EAT": 3 * 3600,
        "ECT": -5 * 3600,
        "EDT": -4 * 3600,
        "EEST": 3 * 3600,
        "EET": 2 * 3600,
        "EGST": 0 * 3600,
        "EGT": -1 * 3600,
        "EST": -5 * 3600,
        "ET": -5 * 3600,
        "F": 6 * 3600,
        "FET": 3 * 3600,
        "FJST": 13 * 3600,
        "FJT": 12 * 3600,
        "FKST": -3 * 3600,
        "FKT": -4 * 3600,
        "FNT": -2 * 3600,
        "G": 7 * 3600,
        "GALT": -6 * 3600,
        "GAMT": -9 * 3600,
        "GET": 4 * 3600,
        "GFT": -3 * 3600,
        "GILT": 12 * 3600,
        "GMT": 0 * 3600,
        "GST": 4 * 3600,
        "GYT": -4 * 3600,
        "H": 8 * 3600,
        "HDT": -9 * 3600,
        "HKT": 8 * 3600,
        "HOVST": 8 * 3600,
        "HOVT": 7 * 3600,
        "HST": -10 * 3600,
        "I": 9 * 3600,
        "ICT": 7 * 3600,
        "IDT": 3 * 3600,
        "IOT": 6 * 3600,
        "IRDT": 4.5 * 3600,
        "IRKST": 9 * 3600,
        "IRKT": 8 * 3600,
        "IRST": 3.5 * 3600,
        "IST": 5.5 * 3600,
        "JST": 9 * 3600,
        "K": 10 * 3600,
        "KGT": 6 * 3600,
        "KOST": 11 * 3600,
        "KRAST": 8 * 3600,
        "KRAT": 7 * 3600,
        "KST": 9 * 3600,
        "KUYT": 4 * 3600,
        "L": 11 * 3600,
        "LHDT": 11 * 3600,
        "LHST": 10.5 * 3600,
        "LINT": 14 * 3600,
        "M": 12 * 3600,
        "MAGST": 12 * 3600,
        "MAGT": 11 * 3600,
        "MART": 9.5 * 3600,
        "MAWT": 5 * 3600,
        "MDT": -6 * 3600,
        "MHT": 12 * 3600,
        "MMT": 6.5 * 3600,
        "MSD": 4 * 3600,
        "MSK": 3 * 3600,
        "MST": -7 * 3600,
        "MT": -7 * 3600,
        "MUT": 4 * 3600,
        "MVT": 5 * 3600,
        "MYT": 8 * 3600,
        "N": -1 * 3600,
        "NCT": 11 * 3600,
        "NDT": 2.5 * 3600,
        "NFT": 11 * 3600,
        "NOVST": 7 * 3600,
        "NOVT": 7 * 3600,
        "NPT": 5.5 * 3600,
        "NRT": 12 * 3600,
        "NST": 3.5 * 3600,
        "NUT": -11 * 3600,
        "NZDT": 13 * 3600,
        "NZST": 12 * 3600,
        "O": -2 * 3600,
        "OMSST": 7 * 3600,
        "OMST": 6 * 3600,
        "ORAT": 5 * 3600,
        "P": -3 * 3600,
        "PDT": -7 * 3600,
        "PET": -5 * 3600,
        "PETST": 12 * 3600,
        "PETT": 12 * 3600,
        "PGT": 10 * 3600,
        "PHOT": 13 * 3600,
        "PHT": 8 * 3600,
        "PKT": 5 * 3600,
        "PMDT": -2 * 3600,
        "PMST": -3 * 3600,
        "PONT": 11 * 3600,
        "PST": -8 * 3600,
        "PT": -8 * 3600,
        "PWT": 9 * 3600,
        "PYST": -3 * 3600,
        "PYT": -4 * 3600,
        "Q": -4 * 3600,
        "QYZT": 6 * 3600,
        "R": -5 * 3600,
        "RET": 4 * 3600,
        "ROTT": -3 * 3600,
        "S": -6 * 3600,
        "SAKT": 11 * 3600,
        "SAMT": 4 * 3600,
        "SAST": 2 * 3600,
        "SBT": 11 * 3600,
        "SCT": 4 * 3600,
        "SGT": 8 * 3600,
        "SRET": 11 * 3600,
        "SRT": -3 * 3600,
        "SST": -11 * 3600,
        "SYOT": 3 * 3600,
        "T": -7 * 3600,
        "TAHT": -10 * 3600,
        "TFT": 5 * 3600,
        "TJT": 5 * 3600,
        "TKT": 13 * 3600,
        "TLT": 9 * 3600,
        "TMT": 5 * 3600,
        "TOST": 14 * 3600,
        "TOT": 13 * 3600,
        "TRT": 3 * 3600,
        "TVT": 12 * 3600,
        "U": -8 * 3600,
        "ULAST": 9 * 3600,
        "ULAT": 8 * 3600,
        "UTC": 0 * 3600,
        "UYST": -2 * 3600,
        "UYT": -3 * 3600,
        "UZT": 5 * 3600,
        "V": -9 * 3600,
        "VET": -4 * 3600,
        "VLAST": 11 * 3600,
        "VLAT": 10 * 3600,
        "VOST": 6 * 3600,
        "VUT": 11 * 3600,
        "W": -10 * 3600,
        "WAKT": 12 * 3600,
        "WARST": -3 * 3600,
        "WAST": 2 * 3600,
        "WAT": 1 * 3600,
        "WEST": 1 * 3600,
        "WET": 0 * 3600,
        "WFT": 12 * 3600,
        "WGST": -2 * 3600,
        "WGT": -3 * 3600,
        "WIB": 7 * 3600,
        "WIT": 9 * 3600,
        "WITA": 8 * 3600,
        "WST": 14 * 3600,
        "WT": 0 * 3600,
        "X": -11 * 3600,
        "Y": -12 * 3600,
        "YAKST": 10 * 3600,
        "YAKT": 9 * 3600,
        "YAPT": 10 * 3600,
        "YEKST": 6 * 3600,
        "YEKT": 5 * 3600,
        "Z": 0 * 3600,
    }
    # 部分时区标识被识别, 需要额外添加timezone_info字典来进行处理
    # 相关示例 https://stackoverflow.com/questions/51206500/how-to-convert-a-string-datetime-with-unknown-timezone-to-timestamp-in-python
    # 时区查询 https://www.timeanddate.com/time/zones/

    try:
        time_parse = parse(str_time, tzinfos=timezone_info)  # 解析日期为datetime型
    except ValueError, e:
        return str_time

    try:
        time_parse = time_parse.astimezone(tz=utc_timezone)  # 有时区转换为北京时间
    except ValueError, e:
        time_parse = utc_timezone.localize(time_parse)  # 无时区转换为localtime，即北京时间
    D, T = str(time_parse).split(" ", 1)
    return D + " " + T[:8]


def get_status_value(status_str):
    """
    将域名状态字符串转换成状态值
    :param status_str: 域名状态字符串
    :return: 状态值［若无状态则默认为30(NOSTATUS),
                   非标准状态值只变成大写"""
    global WHOIS_STATUS_DICT
    status_return = ""
    if status_str == "":
        return "30"
    infos = status_unite(status_str).split(";")
    for status in infos:
        status_value = WHOIS_STATUS_DICT.get(status, "0")
        if status_value == "0":
            status_value = status
        status_return += status_value
        status_return += ";"
    return status_return.strip(";")


def status_unite(status):
    """状态字符串格式处理"""
    while status.find(" ") != -1:
        status = status.replace(" ", ";")
    while status.find("-") != -1:
        status = status.replace("-", ";")
    return status.upper()


def is_xxx_exist(data):
    """用来判断com_manage函数中，得到的whois信息是否包含xxx标志，若包括则需要重新发送"""
    if data.find("\"xxx\"") != -1 and data.find("\"=xxx\"") != -1:
        return True
    else:
        return False


def extract_sec_server(data, domain):
    """提取原始whois信息中的，二级whois服务器"""
    if not data:
        return False
    if data.find("Domain Name: %s" % domain.upper()) != -1:
        pos = data.find("Domain Name: %s" % domain.upper())
        data = data[pos:]
        pattern = re.compile(r"Whois Server:.*|WHOIS Server:.*")
        sec_whois_server = ""
        for match in pattern.findall(data):
            if match.find("Server:") != -1:
                sec_whois_server = match.split(":")[1].strip()
        return False if sec_whois_server == "" else sec_whois_server
    elif data.find("Registrar WHOIS Server:") != -1:  # ws二级服务器
        pattern = re.compile(r"Registrar WHOIS Server:.*")
        sec_whois_server = ""
        for match in pattern.findall(data):
            if match.find("Server:") != -1:
                sec_whois_server = match.split(":")[1].strip()
        return False if sec_whois_server == "" else sec_whois_server
    else:
        return False


def extract_WHOIS_info(domain_punycode,
                       tld,
                       whois_addr,
                       data,
                       flag,
                       format_time=True,
                       format_domain_status=True,
                       list_name_server=True,
                       socket_time_out=5,
                       socket_retry_time=1,
                       use_sock_proxy=False,
                       proxy_type="SOCKS5",
                       proxy_ip="",
                       proxy_port="",
                       proxy_username="",
                       proxy_password="",
                       use_relay_WHOIS_server=False
                       ):
    # type: (str, str, str, str, int, bool, bool, bool, int, int, bool, str, str, str, str, str, bool) -> dict
    """
    :param domain_punycode:             punycode格式的域名
    :param tld:                         顶级域
    :param whois_addr:                  whois服务器
    :param data:                        服务器返回数据
    :param flag:                        数据正确性标记位
    :param format_time:                 标准化时间
    :param format_domain_status:        标准化域名标记
    :param list_name_server:            列表格式记录域名NS服务器标记
    :param socket_time_out:             socket 连接超时时间
    :param socket_retry_time:           socket 连接最大重试次数
    :param use_sock_proxy:              是否使用socks代理
    :param proxy_type:                  代理的类型(仅支持 SOCKS4 , SOCKS5 不支持 HTTP,HTTPS 代理)
    :param proxy_ip:                    代理ip
    :param proxy_port:                  代理端口
    :param proxy_username:              代理用户名
    :param proxy_password:              代理密码
    :param use_relay_WHOIS_server:      是否使用转发服务器查询标记
    :return: whois 信息字典
    """
    # 返回结果初始化
    global WHOIS_RECORD, CHOSE_WHOIS_server, ABLE_FORMAT_TIME
    domain_whois = copy.deepcopy(WHOIS_RECORD)
    domain_whois["domain"] = domain_punycode
    domain_whois["tld"] = tld
    domain_whois["top_whois_server"] = whois_addr
    domain_whois["top_whois_detail"] = data
    domain_whois["flag"] = flag

    # 1. 一级WHOIS错误,未找到WHOIS服务器,WHOIS信息为空
    if domain_whois["flag"] < 0:  # ,错误数据直接返回 粗处理直接返回
        return domain_whois

    whois_details_first = data
    whois_details_sec = ""
    whois_extract_func = CHOSE_WHOIS_server.get_whois_func(whois_addr)
    sec_whois_srv = ""
    # 处理原始whois数据
    if whois_extract_func == "com_manage" and tld in ["com", "net"]:
        # 针对com,net 等具有二级服务器的域名进行特殊处理
        # 1，处理含有 "xxx="的情况
        if is_xxx_exist(whois_details_first):
            whois_details_first = WHOIS_srv_connect("=" + domain_punycode,
                                                    whois_addr,
                                                    socket_time_out=socket_time_out,
                                                    socket_retry_time=socket_retry_time,
                                                    use_sock_proxy=use_sock_proxy,
                                                    proxy_type=proxy_type,
                                                    proxy_ip=proxy_ip,
                                                    proxy_port=proxy_port,
                                                    proxy_username=proxy_username,
                                                    proxy_password=proxy_password,
                                                    use_relay_WHOIS_server=use_relay_WHOIS_server
                                                    )
            if whois_details_first.startswith("SOCKET ERROR"):
                domain_whois["flag"] = FLAG_TOP_WHOIS_FAILED  # WHOIS服务器交互过程中出现异常
            elif not whois_details_first:
                domain_whois["flag"] = FLAG_EMPTY_WHOIS_INFO  # 获取到空数据

        if domain_whois["flag"] < 0:  # 错误数据直接返回 粗处理结果不调用提取函数
            return domain_whois

        # 2，处理二级whois服务器
        sec_whois_srv = extract_sec_server(whois_details_first, domain_punycode)
        if sec_whois_srv:  # 如果获取到了二级whois地址,更新sec_whois并重新获取数据
            domain_whois["sec_whois_server"] = sec_whois_srv
            whois_details_sec = WHOIS_srv_connect(domain_punycode,
                                                  sec_whois_srv,
                                                  socket_time_out=socket_time_out,
                                                  socket_retry_time=socket_retry_time,
                                                  use_sock_proxy=use_sock_proxy,
                                                  proxy_type=proxy_type,
                                                  proxy_ip=proxy_ip,
                                                  proxy_port=proxy_port,
                                                  proxy_username=proxy_username,
                                                  proxy_password=proxy_password,
                                                  use_relay_WHOIS_server=use_relay_WHOIS_server
                                                  )
            if whois_details_first.startswith("SOCKET ERROR"):
                domain_whois["flag"] = FLAG_SEC_WHOIS_FAILED  # WHOIS服务器交互过程中出现异常
            elif not whois_details_sec:
                domain_whois["flag"] = FLAG_EMPTY_WHOIS_INFO  # 获取到空数据
            domain_whois["sec_whois_detail"] = whois_details_sec

        else:
            domain_whois["flag"] = FLAG_NO_SEC_WHOI_ADDR  # 没有获取到二级WHOIS服务器

    if whois_details_sec:
        domain_whois["details"] = whois_details_first + "\n---\n" + whois_details_sec
    else:
        domain_whois["details"] = whois_details_first

    # 使用提取函数处理whois获取字典 依次解析一级/二级WHOIS数据
    try:
        sec_domain_whois = copy.deepcopy(domain_whois)
        domain_whois = getattr(WHOIS_parser, whois_extract_func)(whois_details_first, domain_whois)
        if whois_details_sec and sec_whois_srv:
            sec_whois_extract_func = CHOSE_WHOIS_server.get_whois_func(sec_whois_srv)
            sec_domain_whois = getattr(WHOIS_parser, sec_whois_extract_func)(whois_details_sec, sec_domain_whois)
            # 合并字典
            for k in sec_domain_whois.keys():  # 只更新部分字段
                if k in ["sponsoring_registrar",
                         "sec_whois_server",
                         "reg_name",
                         "reg_phone",
                         "reg_email",
                         "org_name",
                         "creation_date",
                         "expiration_date",
                         "updated_date",
                         "name_server"]:
                    if sec_domain_whois[k].strip():
                        domain_whois[k] = sec_domain_whois[k]
    except Exception as extract_error:
        domain_whois["flag"] = FLAG_INFO_EXTRACT_FAILED

    # 处理状态值、标准化时间时间字符串
    if format_domain_status:
        domain_whois["domain_status"] = get_status_value(domain_whois["domain_status"])
    if format_time and ABLE_FORMAT_TIME:
        domain_whois["creation_date"] = format_timestamp(domain_whois["creation_date"])
        domain_whois["expiration_date"] = format_timestamp(domain_whois["expiration_date"])
        domain_whois["updated_date"] = format_timestamp(domain_whois["updated_date"])
    if list_name_server:
        domain_whois["name_server"] = domain_whois["name_server"].split(";")
    return domain_whois


if __name__ == '__main__':
    # use demo
    data = WHOIS_srv_connect("baidu.com", "whois.verisign-grs.com")
    wr = extract_WHOIS_info("baidu.com", "com", "whois.verisign-grs.com", data, 1)
    print data
    print wr
