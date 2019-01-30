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
import pytz
import copy
from dateutil.parser import parse

import WHOIS_parser
from WHOIS_connect import WHOIS_srv_connect

utc_timezone = pytz.utc  # 设置utc时区
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
    try:
        time_parse = parse(str_time)  # 解析日期为datetime型
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
                       format_domain_status=True):
    # type: (str, str, str, str, int, bool, bool) -> dict
    """
    :param domain_punycode: punycode格式的域名
    :param tld: 顶级域
    :param whois_addr: whois服务器
    :param data: 服务器返回数据
    :param flag: 数据正确性标记位
    :param format_time: 标准化时间
    :param format_domain_status: 标准化域名标记
    :return: whois 信息字典
    """
    # 返回结果初始化
    global WHOIS_RECORD, CHOSE_WHOIS_server
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
            whois_details_first = WHOIS_srv_connect("=" + domain_punycode, whois_addr)
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
            whois_details_sec = WHOIS_srv_connect(domain_punycode, sec_whois_srv)
            if whois_details_first.startswith("SOCKET ERROR"):
                domain_whois["flag"] = FLAG_SEC_WHOIS_FAILED  # WHOIS服务器交互过程中出现异常
            elif not whois_details_sec:
                domain_whois["flag"] = FLAG_EMPTY_WHOIS_INFO  # 获取到空数据
            domain_whois["sec_whois_detail"] = whois_details_sec

        else:
            domain_whois["flag"] = FLAG_NO_SEC_WHOI_ADDR  # 没有获取到二级WHOIS服务器

    domain_whois["details"] = whois_details_first + "\n##############################\n" + whois_details_sec

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
    if format_time:
        domain_whois["creation_date"] = format_timestamp(domain_whois["creation_date"])
        domain_whois["expiration_date"] = format_timestamp(domain_whois["expiration_date"])
        domain_whois["updated_date"] = format_timestamp(domain_whois["updated_date"])

    return domain_whois


if __name__ == '__main__':
    # use demo
    data = WHOIS_srv_connect("baidu.com", "whois.verisign-grs.com")
    wr = extract_WHOIS_info("baidu.com", "com", "whois.verisign-grs.com", data, 1)
