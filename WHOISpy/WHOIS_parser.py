#!/usr/bin/env python
# encoding:utf-8

"""
WHOIS parser

"""
import os
import re


class WHOIS_info_extract_func(object):
    """获取whois服务器对应的提取函数"""

    # Singleton
    _instance = None

    def __new__(cls, *args, **kw):
        if not cls._instance:
            cls._instance = super(WHOIS_info_extract_func, cls).__new__(cls, *args, **kw)
        return cls._instance

    def __init__(self):
        """数据初始化"""
        self.server_func_dict = {}
        # 读取配置文件,获取WHOIS服务器与解析函数的映射关系
        extract_func_file_path = os.path.join(os.getcwd(),
                                              os.path.dirname(__file__),
                                              "data",
                                              "WHOIS_extract_func.dat")
        with open(extract_func_file_path) as wf:
            extract_file = list(line for line in wf.read().splitlines() if line and not line.startswith("#"))

        for line in extract_file:
            [srv, func] = line.split(":")
            self.server_func_dict[srv.strip()] = func.strip()

    def get_whois_func(self, whois_srv):
        """
        获取whois对应的提取函数名称
        :param whois_srv: whois服务器
        :return: 对应的提取函数名称 (找不到则默认返回通用提取函数 general_manage)
        """
        result = self.server_func_dict.get(whois_srv, [])
        return "general_manage" if not result else result
 

def general_manage(data, domain_whois):
    sign_not_exist_list = ["No match for", "Available\nDomain", "The queried object does not exist:", \
                           "Requested Domain cannot be found", "The queried object does not exist: Domain name", \
                           "No Data Found", "Domain Status: No Object Found", "Domain not found.",
                           "no matching objects found", \
                           "No matching record.", "No match", "\" is available for registration", "\"  not found", \
                           "This domain name has not been registered.", "NOT FOUND", "Status: Not Registered", \
                           "The queried object does not exists", "Not found:", "Object does not exists"
                           ]
    for sign_not_exist in sign_not_exist_list:
        if data.find(sign_not_exist) != -1:
            domain_whois["domain_status"] = "NOTEXIST"
            return domain_whois

    status = ""
    name_server = ""

    pattern = re.compile(r"(Last updated Date ?:.*|Last Updated On ?:.*\
|Update Date ?:.*|Registrant Phone ?:.*|Registrant Name ?:.*\
|Registrant Organization ?:.*|Registrant Email ?:.*\
|Registrant Phone Number ?:.*|Updated Date ?:.*\
|Creation Date ?:.*|Expiration Date ?:.*|Expires On ?:.*\
|Creation date ?:.*|Created Date ?:.*|Registrant Organisation ?:.*\
|Registrant E-mail ?:.*|Update date ?:.*|Created On ?:.*\
|Expiration date ?:.*|Updated date ?:.*|Updated On ?:.*\
|Registrant Firstname ?:.*\nRegistrant Lastname ?:.*|Expiry Date ?:.*\
|Create Date ?:.*|Status:.*|Registrar:.*|Name Server:.*\
|Registration Date:.*|creation date:.*|Nameservers:.*)")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Registrant Phone" or \
                match.split(":")[0].strip() == "Registrant Phone Number":
            domain_whois["reg_phone"] = match.split(":")[1].strip()

        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()

        elif match.find("Firstname") != -1 and match.find("Lastname") != -1:
            reg_name = match.split("\n")[0].split(":")[1].strip() + " " + \
                       match.split("\n")[1].split(":")[1].strip()
            domain_whois["reg_name"] = match.split(":")[1].strip()

        elif match.split(":")[0].strip() == "Registrant Email" or \
                match.split(":")[0].strip() == "Registrant E-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()

        elif match.split(":")[0].strip() == "Registrant Organization" or \
                match.split(":")[0].strip() == "Registrant Organisation":
            domain_whois["org_name"] = match.split(":")[1].strip()

        elif match.split(":")[0].strip() == "Updated Date" or \
                match.split(":")[0].strip() == "Update Date" or \
                match.split(":")[0].strip() == "Last updated Date" or \
                match.split(":")[0].strip() == "Update date" or \
                match.split(":")[0].strip() == "Last Updated On" or \
                match.split(":")[0].strip() == "Updated date" or \
                match.split(":")[0].strip() == "Updated On":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

        elif match.split(":")[0].strip() == "Creation Date" or \
                match.split(":")[0].strip() == "Creation date" or \
                match.split(":")[0].strip() == "Created Date" or \
                match.split(":")[0].strip() == "Created On" or \
                match.split(":")[0].strip() == "Create Date" or \
                match.split(":")[0].strip() == "creation date" or \
                match.find("Registration Date:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()

        elif match.split(":")[0].strip() == "Expiration Date" or \
                match.split(":")[0].strip() == "Expiration date" or \
                match.split(":")[0].strip() == "Expiry Date" or \
                match.split(":")[0].strip() == "Expires On":
            if match.split(":", 1)[1].strip():  # 按照万网的标准 Registry Expiry Date - 过期日期
                # 匹配非空的时间
                domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

        elif match.find("Status:") != -1:
            status += match.split(":", 1)[1].strip().split(" ")[0].strip()
            status += ";"

        elif match.find("Registrar:") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()

        elif match.find("Name Server:") != -1 or \
                match.find("Nameservers:") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


com_manage = general_manage


def cn_manage(data, domain_whois):
    if data.find("No matching record.") != -1 or data.find(
            "the Domain Name you apply can not be registered online. Please consult your Domain Name registrar") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Domain Status:.*|Registrant:.*|Registrant Contact Email:.*\
|Registration Time:.*|Expiration Time:.*|Sponsoring Registrar:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.find("Domain Status:") != -1:
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.find("Registrant:") != -1:
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.find("Registrant Contact Email:") != -1:
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.find("Registration Time:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.find("Expiration Time:") != -1:
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.find("Sponsoring Registrar:") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.find("Name Server:") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ac_manage(data, domain_whois):
    if re.search(r"(Domain .+? is available for purchase)", data) != None:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    status = ""
    name_server = ""
    pattern = re.compile(r"(Status(\s)+?:.*|Expiry(\s)+?:.*|NS.*|Owner(.*\n)+?\n)")
    for match in pattern.findall(data):
        match = match[0]
        if match.split(":")[0].strip() == "Status":
            status += match.split(":")[1].strip()
            status += ";"
        elif match.split(":")[0].find("NS") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].find("Expiry") != -1:
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.find("Owner") != -1:
            infos = match.split("\n")
            domain_whois["reg_name"] = infos[0].split(":")[1].strip()
            if len(infos) > 1:
                domain_whois["org_name"] = infos[1].split(":")[1].strip()

    domain_whois["domain_status"] = status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def ae_manage(data, domain_whois):
    if data.find("No Data Found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    pattern = re.compile(r"(Status:.*|Registrant Contact Name:.*|Registrant Contact Email:.*\
|Registrant Contact Organisation:.*|Name Server:.*)")
    status = ""
    name_server = ""
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            status += match.split(":")[1].strip()
            status += ";"
        elif match.split(":")[0].strip() == "Registrant Contact Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Contact Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Contact Organisation":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def de_manage(data, domain_whois):
    if data.find("Status: free") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    status = ""
    name_server = ""

    pattern = re.compile(r"(Nserver:.*|Status:.*|Changed:.*|)")
    for match in pattern.findall(data):
        if match.find("Nserver:") != -1:
            name_server += match.split(":", 1)[1].strip()
            name_server += ";"
        elif match.find("Status:") != -1:
            status += match.split(":", 1)[1].strip()
            status += ";"
        elif match.find("Changed:") != -1:
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def ee_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Domain:(.*\n)+?delete:)")
    for match in pattern.findall(data):
        match = match[0]
        for line in match.split("\n"):
            if line.find("status:") != -1:
                domain_status += line.split(":")[1].strip().split("(")[0]
                domain_status += ";"
            elif line.find("registered:") != -1:
                domain_whois["creation_date"] = line.split(":", 1)[1].strip()
            elif line.find("changed:") != -1:
                domain_whois["updated_date"] = line.split(":", 1)[1].strip()
            elif line.find("expire:") != -1:
                domain_whois["expiration_date"] = line.split(":", 1)[1].strip()
    pattern = re.compile(r"(Registrant:(.*\n)+?changed:)")
    for match in pattern.findall(data):
        match = match[0]
        for line in match.split("\n"):
            if line.find("name:") != -1:
                domain_whois["reg_name"] = line.split(":")[1].strip()
            elif line.find("email") != -1:
                domain_whois["reg_email"] = line.split(":")[1].strip()

    for match in re.findall(r"(Name servers:(.*\n)+?changed)", data):
        match = match[0]
        for line in match.split("\n"):
            if line.find("nserver:") != -1:
                name_server += line.split(":")[1].strip()
                name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def th_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(
        r"(Registrar:.*|Name Server:.*|Status:.*|Updated date:.*|Created date:.*|Exp date:.*|Domain Holder:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Updated date":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Created date":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Exp date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Holder":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip() + ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def ru_manage(data, domain_whois):
    if data.find("No entries found") != -1 or data.find("blocking: Domain can not be registered"):
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(person:.*|nserver:.*|e-mail:.*|state:.*|registrar:.*|created:.*|paid-till:.*|org:.*|registrar:.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "state":
            domain_status += match.split(":")[1].strip()
            if domain_status.find(",") != -1:
                domain_status = ";".join(domain_status.split(","))
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "person":
            if match.split(":")[1].strip() != "Private Person":
                domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "paid-till":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "org":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "e-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def nz_manage(data, domain_whois):
    if data.find("query_status: 220 Available") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(domain_dateregistered:.*|domain_datebilleduntil:.*|domain_datelastmodified:.*|registrant_contact_name:.*|ns_name.*:.*\
|domain_delegaterequested:.*|registrar_name:.*|registrar_phone:.*|registrar_email:.*|registrant_contact_phone:.*|\
registrant_contact_email:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "domain_dateregistered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "domain_datebilleduntil":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "domain_datelastmodified":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "registrant_contact_name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrant_contact_phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrant_contact_email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar_name":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip()[:-3] == "ns_name":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def sk_manage(data, domain_whois):
    if data.find("Not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Last-update.*|Valid-date.*|dns_name.*|Domain-status.*)")

    for match in pattern.findall(data):
        if match.find("Last-update") != -1:
            domain_whois["updated_date"] = re.split(r"\s{2,}", match, 1)[1].strip()
        elif match.find("Valid-date") != -1:
            domain_whois["expiration_date"] = re.split(r"\s{2,}", match, 1)[1].strip()
        elif match.find("dns_name") != -1:
            name_server += re.split(r"\s{2,}", match, 1)[1].strip() + ";"
        elif match.find("Domain-status") != -1:
            domain_status = re.split(r"\s{2,}", match, 1)[1].strip() + ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def sg_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(
        r"(Registrar:.*|Creation Date:.*|Modified Date:.*|Expiration Date:.*|Domain Status:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Modified Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
    for match in re.findall(r"(Registrant:(.*\n)*?.*Name:.*)", data):
        for line in match[0].split("\n"):
            if line.find("Name") != -1:
                domain_whois["reg_name"] = line.split(":", 1)[1].strip()
    for match in re.findall(r"(Name Servers:(.*\n)*?.*\n\n)", data):
        for line in match[0].split("\n"):
            if len(line) > 1 and line.find("Name Servers:") == -1:
                name_server += line.strip() + ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ro_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Registered On:.*|Registrar:.*|Domain Status:.*|Nameserver:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registered On":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Nameserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def rs_manage(data, domain_whois):
    if data.find("Domain is not registered") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Domain status:.*|Registration date:.*|Modification date:.*|\
Expiration date:.*|Registrar:.*|Registrant:.*|DNS:.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registration date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Modification date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "DNS":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def qa_manage(data, domain_whois):
    if data.find("No Data Found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Last Modified:.*|Registrar Name:.*|Status:.* |Registrant Contact Name:.*|\
Registrant Contact Email:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip() + ";"
        elif match.split(":")[0].strip() == "Registrant Contact Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrar Name:":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Last Modified":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Contact Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def pf_manage(data, domain_whois):
    if data.find("Domain unknown") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Status :.*|Created.*|Last renewed.*|Expire.*|\
|Name server.*|Registrar Company Name :.*|Registrant Name :.*|Registrant Company Name.*)")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip().find("Created") != -1:
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Last renewed") != -1:
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Expire") != -1:
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Registrar Company Name") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Registrant Name") != -1:
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Name server") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.find("Registrant Company Name") != -1:
            domain_whois["org_name"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def om_manage(data, domain_whois):
    if data.find("No Data Found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Last Modified:.*|Registrar Name.*|Status.*|Registrant Contact Name.*|\
|Registrant Contact Email.*|Name Server:.*|)")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip().find("Last Modified") != -1:
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip().find("Registrant Contact Email") != -1:
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Registrar Name") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Registrant Contact Name") != -1:
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Name Server") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def co_za_manage(data, domain_whois):
    if data.find("Available") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Registrant:\n.*|Email:.*|Tel:.*|Registrar:\n.*\
|Registration Date:.*|Renewal Date:.*|Name Servers:(\n.*)*?\n\n|Domain Status:\n.*|)")

    for match in pattern.findall(data):
        match = match[0]
        if match.find("Domain Status:") != -1:
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.find("Registrant:") != -1:
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.find("Email:") != -1:
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.find("Tel:") != -1:
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.find("Registration Date:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.find("Renewal Date:") != -1:
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.find("Registrar:") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.find("Name Servers:") != -1:
            for line in match.split("\n"):
                if len(line) > 2 and line.find("Name Servers:") == -1:
                    name_server += line.strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def si_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(registrar:.*|nameserver:.*|registrant:.*|status:.*|created:.*|expire:.*|nameserver:.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nameserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "registrant":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "status":
            domain_status += ";".join(match.split(":")[1].strip().split(",")) + ";"
        elif match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "expire":
            domain_whois["expiration_date"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def uk_manage(data, domain_whois):
    if data.find("This domain name has not been registered.") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    name_server = ""
    domain_status = ""
    pattern = re.compile(r"(Registrant:.*\n.*|Registrar:.*\n.*|Registered on:.*\
|Expiry date:.*|Last updated:.*|Name servers:.*(\n.*)+?\n\r\n)")
    for match in pattern.findall(data):
        match = match[0]
        if match.find("Registrant:") != -1:
            for temp in match.split("\n"):
                if len(temp) > 2 and temp.find("Registrant:") == -1:
                    domain_whois["reg_name"] = temp.strip()
        elif match.find("Name servers:") != -1:
            for line in match.split("\n"):
                if len(line) > 2 and line.find("Name servers:") == -1:
                    name_server += line.strip() + ";"
        elif match.find("Registered on:") != -1:
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.find("Expiry date:") != -1:
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.find("Last updated") != -1:
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.find("Registrar:") != -1:
            for temp in match.split("\n"):
                if len(temp) > 2 and temp.find("Registrar") == -1:
                    domain_whois["sponsoring_registrar"] = temp.strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def tm_manage(data, domain_whois):
    if data.find("available for purchase") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Status :.*|Expiry :.*|NS.*?:.*|Owner Name.*:.*|Owner OrgName.*:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip() + ";"
        elif match.split(":")[0].strip() == "Expiry":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Owner Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Owner OrgName":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(" ")[0] == "NS":
            name_server += match.split(":")[1].strip() + ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def so_manage(data, domain_whois):
    if data.find("Not found:") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Sponsoring Registrar:.*|Domain Status:.*\
|Registrant Internationalized Name:.*|Registrant Internationalized Organization:.*|Registrant Voice Number:.*\
|Registrant Email:.*|Name Server:.*|Creation Date:.*|Expiration Date:.*\
|Last Updated On:.*| )")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Internationalized Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Internationalized Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Voice Number":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip() + ";"
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Last Updated On":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def tf_manage(data, domain_whois):
    if data.find("No entries found in the AFNIC Database") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    for match in re.findall(r"(nserver:.*)", data):
        if match.find("nserver:") != -1:
            name_server += match.split(":")[1].strip() + ";"
    holder_count = ""
    for match2 in re.findall(r"(domain:.*(\n.*)+?\n\n)", data):
        for match in re.findall(r"(holder-c:.*|registrar:.*|Expiry Date:.*|created:.*|last-update:.*|status:.*)"
                , match2[0]):
            if match.find("holder-c:") != -1:
                holder_count = match.split(":")[1].strip()
            elif match.find("status:") != -1:
                domain_status += match.split(":")[1].strip() + ";"
            elif match.find("created:") != -1:
                domain_whois["creation_date"] = match.split(":")[1].strip()
            elif match.find("last-update:") != -1:
                domain_whois["updated_date"] = match.split(":")[1].strip()
            elif match.find("Expiry Date:") != -1:
                domain_whois["expiration_date"] = match.split(":")[1].strip()
            elif match.find("registrar") != -1:
                domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()

    for match2 in re.findall(r"(nic-hdl:(.*\n)+?source:)", data):
        sign = False
        temp_count = ""
        for line in match2[0].split("\n"):
            if line.find("nic-hdl:") != -1:
                temp_count = line.split(":")[1].strip()
                if temp_count == holder_count:
                    sign = True
        if sign is False:
            continue
        pattern = re.compile(r"(contact:.*|phone:.*|e-mail:.*)")
        for match in pattern.findall(match2[0]):
            if match.find("contact") != -1:
                domain_whois["reg_name"] = match.split(":")[1].strip()
            elif match.find("phone") != -1:
                domain_whois["reg_phone"] = match.split(":")[1].strip()
            elif match.find("e-mail") != -1:
                domain_whois["reg_email"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def st_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(created-date:.*|updated-date:.*|expiration-date:.*\
|registrant-organization:.*|registrant-name:.*|registrant-phone:.*|registrant-email:.*|nameserver:.*)")
    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "registrant-phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrant-email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrant-name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "created-date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "updated-date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "expiration-date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "registrant-organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nameserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def sn_manage(data, domain_whois):
    if data.find('NOT FOUND') != -1:
        domain_whois['domain_status'] = 'NOTEXIST'
        return domain_whois
    domain_status = ''
    name_server = ''
    pattern = re.compile(r'(Date de creation:.*|Derniere modification:.*\
|Date d.expiration:.*|Nom Registrant.*|Telephone Registrant:.*\
|Courriel Registrant.:.*|Serveur.*?:.*|Registrar.*)')
    for match in pattern.findall(data):
        if match.split(':')[0].strip() == 'Telephone Registrant':
            domain_whois['reg_phone'] = match.split(':')[1].strip()
        elif match.split(':')[0].strip() == 'Courriel Registrant.':
            domain_whois['reg_email'] = match.split(':')[1].strip()
        elif match.split(':')[0].strip() == 'Nom Registrant':
            domain_whois['reg_name'] = match.split(':')[1].strip()
        elif match.split(':')[0].strip() == "Date de creation":
            domain_whois['creation_date'] = match.split(':', 1)[1].strip()
        elif match.split(':')[0].strip() == 'Derniere modification':
            domain_whois['updated_date'] = match.split(':', 1)[1].strip()
        elif match.split(':')[0].strip() == "Date d'expiration":
            domain_whois['expiration_date'] = match.split(':', 1)[1].strip()
        elif match.find('Serveur') != -1:
            name_server += match.split(':')[1].strip()
            name_server += ";"
    domain_whois['domain_status'] = domain_status.strip(';')
    domain_whois['name_server'] = name_server.strip(';')
    return domain_whois


def sh_manage(data, domain_whois):
    if data.find("available for purchase") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Status :.*|Expiry :.*|Owner Name.*:.*|Owner OrgName.*|NS.*|>*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip() + ";"
        elif match.split(":")[0].strip() == "Expiry":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Owner Name":
            domain_whois["reg_name"] += match.split(":")[1].strip()
        elif match.find("Owner OrgName") != -1:
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("NS") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def pr_manage(data, domain_whois):
    if data.find("not registered") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Created On:.*|Expires On:.*|DNS:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Created On":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expires On":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "DNS":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    pattern4 = re.compile(r"(Contact:.*Registrant([\s\S]*)Contact:.*Administrative)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(Organization:.*|Name:.*|Phone:.*|E-mail:.*|)")
        data3 = "".join(tuple(match4)[0])
        for match5 in pattern5.findall(data3):
            if match5.split(":")[0].strip() == "Organization":
                domain_whois["org_name"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "Name":
                domain_whois["reg_name"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "Phone":
                domain_whois["reg_phone"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "E-mail":
                domain_whois["reg_email"] = match5.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ly_manage(data, domain_whois):
    if data.find("Not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Created:.*|Updated:.*|Expired:.*\
|Domain Status:.*|Domain servers in listed order:.*(\n.*)+?\n\n|Registrant:.*(\n.*)+?\n\n)")
    for match in pattern.findall(data):
        match = match[0]
        if match.find("Registrant:") != -1:
            infos = match.split("\n")
            domain_whois["reg_name"] = infos[1].strip()
            for line in infos:
                if line.find("Phone:") != -1:
                    domain_whois["reg_phone"] = line.split(":")[1].strip()
                elif line.find("@") != -1:
                    domain_whois["reg_email"] = line.strip()
        elif match.find("Domain Status:") != -1:
            domain_status += match.split(":")[1].strip() + ";"
        elif match.split(":")[0].strip() == "Created":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Updated":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expired":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.find("Domain servers in listed order:") != -1:
            for line in match.split("\n"):
                if line.find("Domain servers in listed order:") == -1 and len(line) > (2):
                    name_server += line.strip() + ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def lv_manage(data, domain_whois):
    if data.find("Status: free") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Nserver:.*|Updated:.*|Status:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Updated":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
    pattern4 = re.compile(r"([Holder].*(\n.*)+?\n\n)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(Email:.*|Phone:.*|Name:.*)")
        data3 = "".join(tuple(match4))
        for match5 in pattern5.findall(data3):
            if match5.split(":")[0].strip() == "Email":
                domain_whois["reg_email"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "Phone":
                domain_whois["reg_phone"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "Name":
                domain_whois["reg_name"] = match5.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def kz_manage(data, domain_whois):
    if data.find("Nothing found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(server.*|Domain created:.*|Last modified :.*|Domain status :.*|Current Registar:.*\
|Using Domain Name.*(\n.*)+?\n\n)")
    for match in pattern.findall(data):
        match = match[0]
        if match.split(":")[0].strip().find("server") != -1:
            if match.split(":")[0].strip().count(".") > 2:  # 用于去掉一行无用的信息
                name_server += match.split(":")[1].strip()
                name_server += ";"
        elif match.split(":")[0].strip() == "Domain created":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Last modified":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain status":
            domain_status += match.split(":")[1].strip().split(" ")[0].strip() + ";"
        elif match.split(":")[0].strip() == "Current Registar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.find("Using Domain Name") != -1:
            for line in match.split("\n"):
                if line.find("Name....") != -1 and line.find("Organization Name") == -1:
                    domain_whois["reg_name"] = line.split(":")[1].strip()
                elif line.find("Organization Name") != -1:
                    domain_whois["org_name"] = line.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def im_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Expiry Date:.*|Name Server:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    pattern2 = re.compile(r"(Domain Managers([\s\S]*)Domain Owners)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(Name:.*|)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "Name":
                domain_whois["sponsoring_registrar"] = match3.split(":")[1].strip()

    pattern4 = re.compile(r"(Domain Owners([\s\S]*)Administrative Contact)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(Name:.*|)")
        data3 = "".join(tuple(match4)[0])
        for match5 in pattern5.findall(data3):
            if match5.split(":")[0].strip() == "Name":
                domain_whois["reg_name"] = match5.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ws_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Registrar WHOIS Server:.*|Updated Date:.*|Creation Date:.*|Registrar Registration Expiration Date:.*|\
Registrar:.*|Registrar Abuse Contact Email:.*|Registrar Abuse Contact Phone:.*|Domain Status:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.find("Domain Status:") != -1:
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.find("Name Server:") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.find("Registrar WHOIS Server: ") != -1:
            domain_whois["top_whois_server"] = match.split(":")[1].strip()
        elif match.find("Updated Date:") != -1:
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.find("Creation Date:") != -1:
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.find("Expiration Date:") != -1:
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.find("Registrar:") != -1:
            domain_whois["reg_name"] = match.split(":", 1)[1].strip()
        elif match.find("Registrar Abuse Contact Email:") != -1:
            domain_whois["reg_email"] = match.split(":", 1)[1].strip()
        elif match.find("Registrar Abuse Contact Phone:") != -1:
            domain_whois["reg_phone"] = match.split(":", 1)[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def au_manage(data, domain_whois):
    if data.find("No Data Found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Status:.*|Registrant Contact Name:.*\
|Registrar Name:.*|Registrant Contact Email:.*|Name Server:.*|Last Modified:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Registrant Contact Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip().split(" ")[0].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Registrant Contact Email":
            domain_whois["reg_email"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrar Name":
            domain_whois["sponsoring_registrar"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Last Modified":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip().find("Name Server") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ax_manage(data, domain_whois):
    if data.find("No records matching") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Name:.*|Organization:.*|Email address:.*|Telephone:.*|Created:.*|Name Serve.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Email address":
            domain_whois["reg_email"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Created":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Telephone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("Name Serve") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ca_manage(data, domain_whois):
    if re.search(r"Domain status:.*available", data) != None:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Domain status:.*|Registrar:.*\n.*Name:.*\
|Registrant:.*\n.*Name:.*|Creation date:.*|Expiry date:.*|Updated date:.*|Name servers:.*(\n.*)+?\n\n)")
    for match in pattern.findall(data):
        match = match[0]
        if match.split(":")[0].strip() == "Creation date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiry date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Updated date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.find("Registrar:") != -1:
            for line in match.split("\n"):
                if line.find("Name:") != -1:
                    domain_whois["sponsoring_registrar"] = line.split(":")[1].strip()
        elif match.find("Registrant:") != -1:
            for line in match.split("\n"):
                if line.find("Name:") != -1:
                    domain_whois["reg_name"] = line.split(":")[1].strip()
        elif match.find("Name servers:") != -1:
            for line in match.split("\n"):
                if len(line) > 2 and line.find("Name servers:") == -1:
                    name_server += line.strip() + ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def dk_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Status:.*|Registered:.*|Expires:.*|Hostname:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expires":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Hostname":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def dm_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(
        r"(registrar:.*|status:.*|created date:.*|updated date:.*|expiration date:.*|owner-name:.*|nameserver:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "created date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "updated date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "expiration date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "owner-name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nameserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.find("registrar:") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def dz_manage(data, domain_whois):
    if data.find("NO OBJECT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(
        r"(Date de creation#.*|Registrar#.*)")
    for match in pattern.findall(data):
        if match.split("#")[0].strip().find("Registrar") != -1:
            domain_whois["sponsoring_registrar"] = match.split("#")[1].strip(". ").strip()
        elif match.split("#")[0].strip().find("Date de creation") != -1:
            domain_whois["creation_date"] = match.split("#")[1].strip(". ").strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def fi_manage(data, domain_whois):
    if data.find("Domain not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(phone:.*|status:.*|created:.*|modified:.*|expires:.*|nserver:.*)")
    for match in pattern.findall(data):
        if match.find("nserver:") != -1:
            name_server += match.split(":")[1].replace("[Ok]", "").strip() + ";"
        elif match.find("phone:") != -1:
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.find("status:") != -1:
            domain_status += match.split(":")[1].strip() + ";"
        elif match.find("created:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.find("modified:") != -1:
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.find("expires:") != -1:
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def gd_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(registrar:.*|status:.*|created date:.*\
|updated date:.*|expiration date:.*|nameserver:.*|owner-organization:.*|owner-name:.*|owner-phone:.*|owner-email:.*)")
    for match in pattern.findall(data):
        if match.find("nameserver:") != -1:
            name_server += match.split(":")[1].strip() + ";"
        elif match.find("owner-phone:") != -1:
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.find("status:") != -1:
            domain_status += match.split(":")[1].strip() + ";"
        elif match.find("created date:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.find("updated date:") != -1:
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.find("expiration date") != -1:
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.find("owner-name:") != -1:
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.find("owner-email") != -1:
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.find("owner-organization") != -1:
            domain_whois["org_name"] = match.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def hk_manage(data, domain_whois):
    if data.find("not been registered") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Domain Status:.*|Registrar Name:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "expire":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrar Name":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"

    pattern2 = re.compile(r"(Name Servers Information:.*(\n.*)*?Status Information:)")
    for match2 in pattern2.findall(data):
        for line in match2[0].split("\n"):
            if len(line) > 2 and line.find("Name Servers Information:") == -1:
                name_server += line.strip() + ";"

    pattern4 = re.compile(r"(Registrant Contact Information:([\s\S]*?)\n\n\n)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(Company English Name.*|Expiry Date:.*|Domain Name Commencement Date:.*\
|Phone:.*|Email:.*)")
        for match5 in pattern5.findall(match4[0]):
            if match5.split(":")[0].strip().find("Company English Name") != -1:
                domain_whois["org_name"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "Expiry Date":
                domain_whois["expiration_date"] = match5.split(":", 1)[1].strip()
            elif match5.split(":")[0].strip() == "Domain Name Commencement Date":
                domain_whois["creation_date"] = match5.split(":", 1)[1].strip()
            elif match5.split(":")[0].strip() == "Phone":
                domain_whois["reg_phone"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "Email":
                domain_whois["reg_email"] = match5.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ug_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    for match in re.findall(r"(Domain:.*(\n.*)+?\n\n)", data):
        for line in match[0].split("\n"):
            if line.find("Description:") != -1:
                domain_whois["reg_name"] = line.split(":")[1].strip()
            elif line.find("Registered:") != -1:
                domain_whois["creation_date"] = line.split(":", 1)[1].strip()
            elif line.find("Expiry:") != -1:
                domain_whois["expiration_date"] = line.split(":", 1)[1].strip()
            elif line.find("Nameserver:") != -1:
                name_server += line.split(":")[1].strip() + ";"
            elif line.find("Updated:") != -1:
                domain_whois["updated_date"] = line.split(":", 1)[1].strip()
            elif line.find("Status:") != -1:
                domain_status += line.split(":")[1].strip() + ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def hr_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    sign = True
    for match in re.findall(r"(descr:.*|expires:.*)", data):
        if match.find("descr:") != -1 and sign:
            domain_whois["reg_name"] = match.split(":")[1].strip()
            sign = False
        elif match.find("expires") != -1:
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def hu_manage(data, domain_whois):
    if data.find("No match") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    for match in re.findall(r"(record created:.*)", data):
        if match.find("record created:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def by_manage(data, domain_whois):
    if data.find("not exists") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(
        r"(Registrar:.*|Updated Date:.*|Creation Date:.*|Expiration Date:.*|Domain Name Administrator:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Name Administrator":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ie_manage(data, domain_whois):
    if data.find("Not Registered") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    sign = True
    pattern = re.compile(r"(descr:.*|registration:.*|renewal:.*|nserver:.*|ren-status:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "registration":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "renewal":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.find("descr:") != -1 and sign:
            domain_whois["reg_name"] = match.split(":")[1].strip()
            sign = False
        elif match.find("ren-status") != -1:
            domain_status += match.split(":")[1].strip() + ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def il_manage(data, domain_whois):
    if data.find("No data was found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    sign = True
    for match in re.findall(r"(descr:.*(\n.*)+?\n\n)", data):
        match = match[0]
        for line in match.split("\n"):
            if sign and line.find("descr:") != -1:
                domain_whois["reg_name"] = line.split(":")[1].strip()
                sign = False
            elif line.find("nserver:") != -1:
                name_server += line.split(":")[1].strip() + ";"
            elif line.find("status:") != -1:
                domain_status += line.split(":")[1].strip() + ";"
            elif line.find("validity:") != -1:
                domain_whois["expiration_date"] = line.split(":", 1)[1].strip()
            elif line.find("phone:") != -1:
                domain_whois["reg_phone"] = line.split(":")[1].strip()
            elif line.find("e-mail:") != -1:
                domain_whois["reg_email"] = line.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def lt_manage(data, domain_whois):
    if re.search(r"Status:.*available", data) != None:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Status:.*|Registered:.*|Registrar:.*|Nameserver:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Nameserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def lu_manage(data, domain_whois):
    if data.find("No such domain") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(domaintype:.*|nserver:.*|registered:.*|org-name:.*|registrar-name:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "domaintype":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "registrar-name":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "org-name":
            domain_whois["org_name"] = match.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def mx_manage(data, domain_whois):
    if data.find("Object_Not_Found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Created On:.*|Expiration Date:.*|Last Updated On:.*|Registrar:.*|DNS:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Created On":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Last Updated On":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "DNS":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    for match in re.findall(r"(Registrant:.*\n.*Name:.*)", data):
        for line in match.split("\n"):
            if line.find("Name:") != -1:
                domain_whois["reg_name"] = line.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(":")
    return domain_whois


def nc_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Created on.*:.*|Expires on.*:.*|Last updated on.*:.*\
|Domain server.*|Registrant name.*:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip().find("Domain server") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Created on":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expires on":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrant name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def nu_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois
    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(status:.*|holder:.*|created:.*|modified:.*|expires:.*\
|nserver:.*|registrar:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "expires":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "modified":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "holder":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def sm_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Owner:.*(\n.*)+?\n\n|Registration date:.*|Status:.*|DNS Servers:.*(\n.*)\n\n)")
    for match in pattern.findall(data):
        match = match[0]
        if match.find("Owner:") != -1:
            domain_whois["reg_name"] = match.split("\n")[2].strip()
            for line in match.split("\n"):
                if line.find("Phone:") != -1:
                    domain_whois["reg_phone"] = line.split(":")[1].strip()
                elif line.find("Email:") != -1:
                    domain_whois["reg_email"] = line.split(":")[1].strip()
        elif match.find("Registration date:") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.find("Status:") != -1:
            domain_status += match.split(":")[1].strip()
        elif match.find("DNS Servers:") != -1:
            for line in match.split("\n"):
                if len(line) > 2 and line.find("DNS Servers:") == -1:
                    name_server += line.strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


# ----------------Extract Func v2----------------

def ag_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*|Created On:.*|Expiration Date:.*|Last Updated On:.*| )")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Created On":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Last Updated On":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def am_manage(data, domain_whois):
    if data.find("No match") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Status:.*|Registrar:.*|Registered:.*|Last modified:.*|Expires:.*)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registered":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Last modified":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expires":
            domain_whois["expiration_date"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(DNS servers([\s\S]*?)Registered)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("DNS servers") == -1 and line.find("Registered") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def as_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(
        r"(Registrant:\n.*|Registrar:\n.*|Registration status:\n.*|Registered on.*|Registry fee due on.*)")
    for match in pattern3.findall(data):
        if match.find("Registered on") != -1:
            domain_whois["creation_date"] = match.split("on", 1)[1].strip()
        elif match.find("Registry fee due") != -1:
            domain_whois["expiration_date"] = match.split("on", 1)[1].strip()
        elif match.split("\n", 1)[0].find("Registrant") != -1:
            domain_whois["reg_name"] = match.split("\n", 1)[1].strip()
        elif match.split("\n", 1)[0].find("Registrar") != -1:
            domain_whois["sponsoring_registrar"] = match.split("\n", 1)[1].strip()
        elif match.split("\n", 1)[0].find("Registration status") != -1:
            domain_status += match.split("\n", 1)[1].strip()
            domain_status += ";"

    pattern2 = re.compile(r"(Name servers([\s\S]*?)WHOIS lookup made)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Name servers") == -1 and line.find("WHOIS lookup made") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def asia_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant E-mail:.*|Nameservers:.*|Domain Create Date:.*|Domain Expiration Date:.*|Updated Date:.*| )")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant E-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Nameservers":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Domain Create Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def at_manage(data, domain_whois):
    if data.find("nothing found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern2 = re.compile(r"(domain([\s\S]*?)street address)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(registrant:.*|nserver:.*|changed:.*|organization:.*|)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "registrant":
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "changed":
                domain_whois["updated_date"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "organization":
                domain_whois["org_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "nserver":
                name_server += match3.split(":")[1].strip()
                name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def be_manage(data, domain_whois):
    if data.find("AVAILABLE") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Registrant:.*\n.*|Status:.*|Registered:.*|Name:.*|)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Registered":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.find("Registrant") != -1:
            domain_whois["sponsoring_registrar"] = match.split("\n", 1)[1].strip()

    pattern2 = re.compile(r"(Nameservers([\s\S]*?)Keys)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Nameservers") == -1 and line.find("Keys") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def bg_manage(data, domain_whois):
    if data.find("not exist") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    temp = ""

    pattern = re.compile(
        r"(requested on:.*|activated on:.*|expires at:.*|registration status:.*|    Expiration Date:.*|    Domain Status:.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "registration status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Domain Name":
            temp += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "activated on":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "requested on":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "expires at":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    pattern4 = re.compile(r"(ADMINISTRATIVE CONTACT([\s\S]*?)TECHNICAL CONTACT)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(  tel:.*|.*@.*)")
        data3 = "".join(tuple(match4))
        for match5 in pattern5.findall(data3):
            if match5.split(":")[0].strip() == "tel":
                domain_whois["reg_phone"] = match5.split(":")[1].strip()
            elif match5.strip().find("@") != -1:
                domain_whois["reg_email"] = match5.strip()

    pattern2 = re.compile(r"(NAME SERVER([\s\S]*?)DNSSEC)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(.*\..*\..*)")
        data2 = "".join(tuple(match2[0]))  # 这里会匹配出两个，使DNS变成两倍的，所以用[0]
        for match3 in pattern3.findall(data2):
            name_server += match3.strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def bn_manage(data, domain_whois):
    if data.find("No match") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Registrar:.*|Creation Date:.*|Modified Date:.*|Expiration Date:.*|Status:.*)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Modified Date":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(Name Servers:([\s\S]*?)\n)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Name Servers") == -1 and line.find("Registered") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def bo_manage(data, domain_whois):
    if data.find("solo acepta") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Fecha de registro:.*|Fecha de vencimiento:.*)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Fecha de registro":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Fecha de vencimiento":
            domain_whois["expiration_date"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(TITULAR([\s\S]*?)CONTACTO ADMINISTRATIVO)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2))
        pattern = re.compile(r"(Organizacion:.*|Nombre:.*|Email:.*|Telefono.*)")
        for match3 in pattern.findall(data2):
            if match3.split(":")[0].strip() == "Organizacion":
                domain_whois["org_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "Nombre":
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "Email":
                domain_whois["reg_email"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "Telefono":
                domain_whois["reg_phone"] = match3.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def cc_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(   Updated Date:.*|   Creation Date:.*|   Registry Expiry Date:.*|   Sponsoring Registrar:.*|   Domain Status:.*|   Name Server:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip().find("Name Server") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def ceo_manage(data, domain_whois):
    if data.find("not exist") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*|Creation Date:.*|Registry Expiry Date:.*|Updated Date:.*| )")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def cf_manage(data, domain_whois):
    if data.find("Invalid query or domain") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Phone:.*|E-mail:.*|)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Phone":
            domain_whois["reg_phone"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "E-mail":
            domain_whois["reg_email"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(Domain Nameservers([\s\S]*?)Your selected domain)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Domain Nameservers") == -1 and line.find("Your selected domain") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def club_manage(data, domain_whois):
    if data.find("No Domain exists") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*|Creation Date:.*|Registry Expiry Date:.*|Updated Date:.*| )")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def cr_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(registrar:.*|status:.*|registered:.* |changed:.*|expire:.*|org:.*|name:.*|phone:.*|e-mail:.*|nserver:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "org":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "expire":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "changed":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "e-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def cz_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(registrar:.*|registered:.*|changed:.*|expire:.*|nserver:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "expire":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "changed":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    pattern2 = re.compile(r"(expire([\s\S]*?)nsset)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(name:.*|e-mail:.*|)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "name":
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "e-mail":
                domain_whois["reg_email"] = match3.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def edu_manage(data, domain_whois):
    if data.find("No Match") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Domain record activated:.*|Domain record last updated:.*|Domain expires:.*|)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Domain record activated":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain record last updated":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain expires":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(Name Servers([\s\S]*?)Domain record activated)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Name Servers") == -1 and line.find("Domain record activated") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def eu_manage(data, domain_whois):
    if data.find("AVAILABLE") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern2 = re.compile(r"(Registrant([\s\S]*?)Technical)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(Name:.*|Phone:.*|Email:.*)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip().find("Name") != -1:
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip().find("Phone") != -1:
                domain_whois["reg_phone"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip().find("Email") != -1:
                domain_whois["reg_email"] = match3.split(":")[1].strip()

    pattern2 = re.compile(r"(Registrar([\s\S]*?)Name servers)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(Name:.*|)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip().find("Name") != -1:
                domain_whois["sponsoring_registrar"] = match3.split(":")[1].strip()

    pattern2 = re.compile(r"(Name servers([\s\S]*?)Please visit)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Name servers") == -1 and line.find("Please visit") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def gov_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    pattern = re.compile(r"(   Status:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"

    domain_whois["domain_status"] = domain_status.strip(";")

    return domain_whois


def in_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*|Created On:.*|Expiration Date:.*|Last Updated On:.*| )")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Created On":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Last Updated On":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def int_manage(data, domain_whois):
    if data.find("this server does not have") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(nserver:.*|created:.*|changed:.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "changed":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    pattern2 = re.compile(r"(contact:      administrative([\s\S]*?)contact:      technical)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(name:.*|organisation:.*|phone:.*|e-mail:.*|)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "name":
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "organisation":
                domain_whois["org_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "phone":
                domain_whois["reg_phone"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "e-mail":
                domain_whois["reg_email"] = match3.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def io_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Status :.*|Expiry :.*|NS.*|Owner  :.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Expiry":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip().find("NS") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Owner":
            domain_whois["reg_name"] = match.split(":")[1].strip()
            break  # 只取得第一行的信息，即姓名。

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def ir_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(status:.*|holder-c:.*|org:.* |expire-date:.*|created:.*|last-updated:.*|nserver:.*|phone:.*|e-mail:.*|nserver:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "holder-c":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "org":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "expire-date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "last-updated":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "e-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def jp_manage(data, domain_whois):
    if data.find("No match") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(\[Status\].*|\[Name Server\].*|\[Created on\].*|\[Expires on\].*|\
|\[Status\].*|\[Last Updated\].*|\[Name\].*|\[Email\].*|\[Phone\].*|)")
    for match in pattern.findall(data):
        if match.find("Status") != -1:
            domain_status += match.split("]")[1].strip()
            domain_status += ";"
        elif match.find("Registrant") != -1:
            domain_whois["reg_name"] = match.split("]")[1].strip()
        elif match.find("Created on") != -1:
            domain_whois["creation_date"] = match.split("]")[1].strip()
        elif match.find("Expires on") != -1:
            domain_whois["expiration_date"] = match.split("]")[1].strip()
        elif match.find("Last Updated") != -1:
            domain_whois["updated_date"] = match.split("]")[1].strip()
        elif match.find("Email") != -1:
            domain_whois["reg_email"] = match.split("]")[1].strip()
        elif match.find("Phone") != -1:
            domain_whois["reg_phone"] = match.split("]")[1].strip()
        elif match.find("Name") != -1 and match.find("Name Server") == -1:
            domain_whois["reg_name"] = match.split("]")[1].strip()
        elif match.find("Name Server") != -1:
            name_server += match.split("]")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def kr_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Registrant.*:.*|AC E-Mail.*:.*|AC Phone Number.*:.*|Registered Date.*:.*|\
|Last Updated Date.*:.*|Expiration Date.*:.*)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "Registrant":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "AC E-Mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "AC Phone Number":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registered Date":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Last Updated Date":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(Primary Name Server([\s\S]*?)상기 정보는 UTF-8)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        pattern = re.compile(r"(Host Name.*:.*|)")
        for match3 in pattern.findall(data2):
            if match3.split(":")[0].strip() == "Host Name":
                name_server += match3.split(":")[1].strip()
                name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def me_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Domain Create Date:.*|Domain Last Updated Date:.*|Domain Expiration Date:.*|Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*\
|Registrant Organization:.*|Registrant Phone:.*|Registrant E-mail:.*|Nameservers:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Domain Create Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain Last Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant E-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Nameservers":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def mk_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(registrar:.*|registered:.*|changed:.*|expire:.*|nserver:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "expire":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "changed":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    pattern2 = re.compile(r"(expire([\s\S]*?)nsset)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(name:.*|e-mail:.*|)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "name":
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "e-mail":
                domain_whois["reg_email"] = match3.split(":")[1].strip()

    pattern4 = re.compile(r"(Domain Owners([\s\S]*)Administrative Contact)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(Name:.*|)")
        data3 = "".join(tuple(match4)[0])
        for match5 in pattern5.findall(data3):
            if match5.split(":")[0].strip() == "Name":
                domain_whois["reg_name"] = match5.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def mo_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Registrar:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def mobi_manage(data, domain_whois):
    if data.find("NOT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Created On:.*|Last Updated On:.*|Expiration Date:.*|Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*\
|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Created On":
            domain_whois["creation_date"] = match.split(":")[1].strip()[:-3]
        elif match.split(":")[0].strip() == "Last Updated On":
            domain_whois["expiration_date"] = match.split(":")[1].strip()[:-3]
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["updated_date"] = match.split(":")[1].strip()[:-3]
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def moe_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Updated Date:.*|Creation Date:.*|Registry Expiry Date:.*|Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*\
|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def museum_manage(data, domain_whois):
    if data.find("no matching objects found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Created On:.*|Last Updated On:.*|Expiration Date:.*|Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*\
|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Created On":
            domain_whois["creation_date"] = match.split(":")[1].strip()[:-3]
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()[:-3]
        elif match.split(":")[0].strip() == "Last Updated On":
            domain_whois["updated_date"] = match.split(":")[1].strip()[:-3]
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def name_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Sponsoring Registrar:.*|Domain Status:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip() + ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def no_manage(data, domain_whois):
    if data.find("No match") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern3 = re.compile(r"(Name Server Handle.*|Domain Holder Handle.*|Registrar Handle.*)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip().find("Name Server Handle") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip().find("Registrar Handle") != -1:
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(Additional information([\s\S]*?)Email Address.*)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2))
        pattern = re.compile(r"(Name.*|Created.*|Last updated.*|\
    |Phone Number.*|Email Address.*|Type.*)")
        for match in pattern.findall(data2):
            if match.split(":")[0].strip().find("Type") != -1:
                type = match.split(":")[1].strip()
            elif match.split(":")[0].strip().find("Name") != -1:
                if str(type).find("organization") != -1:
                    domain_whois["org_name"] = match.split(":")[1].strip()
                else:
                    domain_whois["reg_name"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip().find("Email Address") != -1:
                domain_whois["reg_email"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip().find("Registrar Handle") != -1:
                domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip().find("Phone Number") != -1:
                domain_whois["reg_phone"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip().find("Created") != -1:
                domain_whois["creation_date"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip().find("Last updated") != -1:
                domain_whois["updated_date"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def nrw_manage(data, domain_whois):
    if data.find("no matching objects found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Update Date:.*|Creation Date:.*|Registry Expiry Date:.*|Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*\
|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Update Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def pe_manage(data, domain_whois):
    if data.find("No Object Found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Admin Email:.*|Name Server:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Admin Email":
            domain_whois["reg_email"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip().find("Name Server") != -1:
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def pl_manage(data, domain_whois):
    if data.find("No information available") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    name_server = ""
    domain_status = ""
    pattern = re.compile(r"(created:.*|last modified:.*|renewal date:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "last modified":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "renewal date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(nameservers([\s\S]*?)created)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("created") == -1:
                    if line.find("nameservers") != -1:
                        name_server += line.strip("nameservers:").strip()
                        name_server += ";"
                    else:
                        name_server += line.strip()
                        name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def re_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(status:.*|holder-c:.*|registrar:.* |Expiry Date:.*|created:.*|last-update:.*|nserver:.*|phone:.*|e-mail:.*|nserver:.*)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "holder-c":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Expiry Date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "last-update":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "e-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def sa_manage(data, domain_whois):
    if data.find("No Match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Created on:.*|Last Updated on:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Created on":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Last Updated on":
            domain_whois["expiration_date"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(Name Servers([\s\S]*?)Created on)")
    for match4 in pattern2.findall(data):
        for line in str(match4[0]).split("\n"):
            if line:
                if line.find("Name Servers") == -1 and line.find(
                        "Created on") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def science_manage(data, domain_whois):
    if data.find("No Domain exists for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Status:.*|Creation Date:.*|Update Date:.*|Registry Expiry Date:.*|Sponsoring Registrar:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*|)")

    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Update Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def scot_manage(data, domain_whois):
    if data.find("no matching objects found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Status:.*|Creation Date:.*|Update Date:.*|Registry Expiry Date:.*|Sponsoring Registrar:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone:.*|Registrant Email:.*|Name Server:.*|)")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Update Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registry Expiry Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone":
            domain_whois["reg_phone"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def tk_manage(data, domain_whois):
    # 两种格式？
    if data.find("Invalid query") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    pattern = re.compile(r"(Domain registered:.*|Record will expire on:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain registered":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Record will expire on":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(Owner contact([\s\S]*?)Admin contact)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(Organization:.*|Name:.*|E-mail:.*|Phone:.*)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "Organization":
                domain_whois["org_name"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "Name":
                domain_whois["reg_name"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "E-mail":
                domain_whois["reg_email"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "Phone":
                domain_whois["reg_phone"] = match3.split(":", 1)[1].strip()
    pattern2 = re.compile(r"(Organisation([\s\S]*?)Domain Nameservers)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(Organization:.*|Name:.*|E-mail:.*|Phone:.*)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "Organization":
                domain_whois["org_name"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "Name":
                domain_whois["reg_name"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "E-mail":
                domain_whois["reg_email"] = match3.split(":", 1)[1].strip()
            elif match3.split(":")[0].strip() == "Phone":
                domain_whois["reg_phone"] = match3.split(":", 1)[1].strip()

    pattern3 = re.compile(r"(Domain Nameservers([\s\S]*?)Domain registered)")
    for match3 in pattern3.findall(data):
        data3 = "".join(tuple(match3)[0])
        for line in data3.split("\n"):
            if line:
                if line.find("Domain Nameservers") == -1 and line.find("Domain registered") == -1:
                    name_server += line.strip()
                    name_server += ";"
    pattern3 = re.compile(r"(Domain Nameservers([\s\S]*?)Your selected domain name)")
    for match3 in pattern3.findall(data):
        data3 = "".join(tuple(match3)[0])
        for line in data3.split("\n"):
            if line:
                if line.find("Domain Nameservers") == -1 and line.find("Your selected domain name") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def tn_manage(data, domain_whois):
    if data.find("NO OBJECT FOUND") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern1 = re.compile(r"(This is JWhoisServer serving.*?----------------------------------------)", re.S)
    pattern = re.compile(
        r"(Status:.*|First Name:.*|Last Name:.*|Date Created:.*|Tel:.*|Expiry date:.*|e-mail:.*|Registrar:.*|Activation:.*|Name Server .*:.*|)")

    if pattern1.findall(data):
        tmp = str(pattern1.findall(data)[0])

    data2 = "".join(tmp)
    # print type(data2)
    # print data2
    for tmp in pattern.findall(data2):
        match = "".join(tmp)
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip(".").strip()
        elif match.split(":")[0].strip() == "Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip(".").strip()
        elif match.split(":")[0].strip() == "Tel":
            domain_whois["reg_phone"] = match.split(":")[1].strip(".").strip()
        elif match.split(":")[0].strip() == "e-mail":
            domain_whois["reg_email"] = match.split(":")[1].strip(".").strip()
        elif match.split(":")[0].strip() == "Activation":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip(".").strip()
        elif match.split(":")[0].strip() == "Name Server (DB)":
            name_server += match.split(":")[1].strip(".").strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Last Name":
            last_name = match.split(":")[1].strip(".").strip()
        elif match.split(":")[0].strip() == "First Name":
            first_name = match.split(":")[1].strip(".").strip()
    domain_whois["reg_name"] = last_name + first_name

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def travel_manage(data, domain_whois):
    if data.find("Not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(
        r"(Sponsoring Registrar:.*|Domain Status:.*|Registrant Name:.*|Registrant Organization:.*|Registrant Phone Number:.*|Registrant Email:.*|Name Server:.*|Domain Registration Date:.*|Domain Expiration Date:.*|Domain Last Updated Date:.*| )")

    for match in pattern.findall(data):

        if match.split(":")[0].strip() == "Sponsoring Registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Phone Number":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrant Email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Name Server":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "Domain Registration Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Domain Last Updated Date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def tw_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(  Domain Status:.*|   Record expires on.*|   Record created on.*|\
|Registration Service Provider:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Domain Status":
            domain_status += match.split(":", 1)[1].strip().split(" ")[0].strip().upper()
            domain_status += ";"
        elif match.split("on")[0].strip() == "Record expires":
            domain_whois["expiration_date"] = match.split("on", 1)[1].strip()
        elif match.split("on")[0].strip() == "Record created":
            domain_whois["creation_date"] = match.split("on", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registration Service Provider":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(   Domain servers in listed order:([\s\S]*?)Registration Service Provider)")
    for match4 in pattern2.findall(data):
        for line in str(match4[0]).split("\n"):
            if line:
                if line.find("Domain servers in listed order") == -1 and line.find(
                        "Registration Service Provider") == -1:
                    name_server += line.strip()
                    name_server += ";"

    pattern4 = re.compile(r"(   Registrant([\s\S]*?)   Administrative Contact)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(      \+.*|.*@.*)")
        data3 = "".join(tuple(match4))
        for match5 in pattern5.findall(data3):
            if match5.strip()[0] == "+":
                domain_whois["reg_phone"] = match5.strip()
            if match5.find("@") != -1:
                for item in match5.split(" "):
                    if item.find("@") != -1:
                        domain_whois["reg_email"] = item.strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def tz_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(nserver:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"

    pattern2 = re.compile(r"(% Timestamp([\s\S]*?)e-mail.*)")
    for match2 in pattern2.findall(data):
        data2 = str(match2[0])
        pattern3 = re.compile(r"(registrar:.*|registered:.*|changed:.*|\
|expire:.*|org:.*|name:.*|phone:.*|e-mail:.*|)")
        for match in pattern3.findall(data2):
            if match.split(":")[0].strip() == "registrar":
                domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip() == "registered":
                domain_whois["creation_date"] = match.split(":", 1)[1].strip()
            elif match.split(":")[0].strip() == "changed":
                domain_whois["updated_date"] = match.split(":", 1)[1].strip()
            elif match.split(":")[0].strip() == "expire":
                domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
            elif match.split(":")[0].strip() == "org":
                domain_whois["org_name"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip() == "name":
                domain_whois["reg_name"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip() == "phone":
                domain_whois["reg_phone"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip() == "e-mail":
                domain_whois["reg_email"] = match.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def ua_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern4 = re.compile(r"(domain([\s\S]*?)% Registrar)")
    for match4 in pattern4.findall(data):
        data3 = "".join(tuple(match4))
        pattern = re.compile(r"(registrant:.*|nserver:.*|status:.*|created:.*|modified:.*|expires:.*)")
        for match in pattern.findall(data3):
            if match.split(":")[0].strip() == "registrant":
                domain_whois["reg_name"] = match.split(":")[1].strip()
            elif match.split(":")[0].strip() == "nserver":
                name_server += match.split(":")[1].strip()
                name_server += ";"
            elif match.split(":")[0].strip() == "status":
                domain_status += match.split(":")[1].strip()
            elif match.split(":")[0].strip() == "created":
                domain_whois["creation_date"] = match.split(":", 1)[1].strip()
            elif match.split(":")[0].strip() == "modified":
                domain_whois["updated_date"] = match.split(":", 1)[1].strip()
            elif match.split(":")[0].strip() == "expires":
                domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(Registrar([\s\S]*?)Registrant)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(organization:.*)")
        # 元组转换成字符串
        data2 = "".join(tuple(match2))
        # print data2
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip() == "organization":
                domain_whois["sponsoring_registrar"] = match3.split(":")[1].strip()

    pattern4 = re.compile(r"(Registrant([\s\S]*?)Administrative Contacts)")
    for match4 in pattern4.findall(data):
        pattern5 = re.compile(r"(person:.*|organization:.*|e-mail:.*|phone:.*)")
        data3 = "".join(tuple(match4))
        for match5 in pattern5.findall(data3):
            if match5.split(":")[0].strip() == "person":
                domain_whois["reg_name"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "organization":
                domain_whois["org_name"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "e-mail":
                domain_whois["reg_email"] = match5.split(":")[1].strip()
            elif match5.split(":")[0].strip() == "phone":
                domain_whois["reg_phone"] = match5.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def uy_manage(data, domain_whois):
    if data.find("No match for") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Registrado por:.*|Ultima Actualizacion:.*|Fecha de Creacion:.*|Estatus del dominio:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Estatus del dominio":
            domain_status += match.split(":", 1)[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Ultima Actualizacion":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Fecha de Creacion":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Registrado por":
            domain_whois["sponsoring_registrar"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(Nombres de Dominio([\s\S]*?)NIC-Uruguay)")
    for match4 in pattern2.findall(data):
        for line in str(match4[0]).split("\n"):
            if line:
                if line.find("Dominio") == -1 and line.find(
                        "NIC-Uruguay") == -1:
                    name_server += line.strip("- ").strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def uz_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Creation Date:.*|Expiration Date:.*|Status:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Creation Date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "Expiration Date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    pattern2 = re.compile(r"(Domain servers in listed order([\s\S]*?)Administrative Contact)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Domain servers in listed order") == -1 and \
                        line.find("Administrative Contact") == -1 and \
                        line.find("not.defined") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def vg_manage(data, domain_whois):
    if data.find("not found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(status:.*|created date:.*|updated date:.*|expiration date:.*|owner-name:.*|\
    |owner-organization:.*|owner-organization:.*|owner-phone:.*|owner-email:.*|nameserver:.*|registrar:.*|)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "owner-name":
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "expiration date":
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "owner-organization":
            domain_whois["org_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "created date":
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "updated date":
            domain_whois["updated_date"] = match.split(":", 1)[1].strip()
        elif match.split(":")[0].strip() == "owner-phone":
            domain_whois["reg_phone"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "owner-email":
            domain_whois["reg_email"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "nameserver":
            if name_server.find(match.split(":")[1].strip()) == -1:
                name_server += match.split(":")[1].strip()
                name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def vu_manage(data, domain_whois):
    if data.find("not valid") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(First Name:.*|Last Name:.*|Date Created:.*|Expiry date:.*|DNS servers.*:.*|)")

    for match in pattern.findall(data):
        if match.find("status:") != -1:
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.find("First Name:") != -1:
            domain_whois["reg_name"] += match.split(":")[1].strip()
        elif match.find("Last Name") != -1:
            domain_whois["reg_name"] += " " + match.split(":")[1].strip()
        elif match.find("DNS servers") != -1:
            name_server += match.split(":", 1)[1].strip()
            name_server += ";"
        elif match.find("Date Created") != -1:
            domain_whois["creation_date"] = match.split(":", 1)[1].strip()
        elif match.find("Expiry date:") != -1:
            domain_whois["expiration_date"] = match.split(":", 1)[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")
    return domain_whois


def yt_manage(data, domain_whois):
    if data.find("No entries found") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""
    owner = ""

    pattern3 = re.compile(r"(status:.*|holder-c:.*|nserver.*|registrar:.*|Expiry Date:.*|created:.*|last-update:.*)")
    for match in pattern3.findall(data):
        if match.split(":")[0].strip() == "nserver":
            name_server += match.split(":")[1].strip()
            name_server += ";"
        elif match.split(":")[0].strip() == "status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "holder-c":
            owner += match.split(":")[1].strip()
            domain_whois["reg_name"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expiry Date":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "last-update":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "registrar":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(nic-hdl([\s\S]*)source)")
    for match2 in pattern2.findall(data):
        data2 = "".join(tuple(match2)).split("source")
        for data3 in data2:
            if data3.find(owner) != -1:
                pattern = re.compile(r"(phone:.*|e-mail:.*|)")
                for match3 in pattern.findall(data3):
                    if match3.split(":")[0].strip() == "phone":
                        domain_whois["reg_phone"] = match3.split(":")[1].strip()
                    elif match3.split(":")[0].strip() == "e-mail":
                        domain_whois["reg_email"] = match3.split(":")[1].strip()

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def ec_manage(data, domain_whois):
    if data.find("Not Registered") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Status:.*|Created:.*|Modified:.*|Expires:.*|Registrar Name:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip() == "Status":
            domain_status += match.split(":")[1].strip()
            domain_status += ";"
        elif match.split(":")[0].strip() == "Created":
            domain_whois["creation_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Modified":
            domain_whois["updated_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Expires":
            domain_whois["expiration_date"] = match.split(":")[1].strip()
        elif match.split(":")[0].strip() == "Registrar Name":
            domain_whois["sponsoring_registrar"] = match.split(":")[1].strip()

    pattern2 = re.compile(r"(Registrant([\s\S]*?)Admin Contact)")
    for match2 in pattern2.findall(data):
        pattern3 = re.compile(r"(International Name:.*|International Organisation:.*|Email Address:.*|Phone Number:.*)")
        data2 = "".join(tuple(match2)[0])
        for match3 in pattern3.findall(data2):
            if match3.split(":")[0].strip().find("International Name") != -1:
                domain_whois["reg_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip().find("International Organisation") != -1:
                domain_whois["org_name"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "Email Address":
                domain_whois["reg_email"] = match3.split(":")[1].strip()
            elif match3.split(":")[0].strip() == "Phone Number":
                domain_whois["reg_phone"] = match3.split(":")[1].strip()

    pattern3 = re.compile(r"(Name Servers:([\s\S]*)Registrar Information)")
    for match2 in pattern3.findall(data):
        data2 = "".join(tuple(match2)[0])
        for line in data2.split("\n"):
            if line:
                if line.find("Name Servers") == -1 and line.find("Registrar Information") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


def nl_manage(domain_whois, data):
    if data.find("is free") != -1:
        domain_whois["domain_status"] = "NOTEXIST"
        return domain_whois

    domain_status = ""
    name_server = ""

    pattern = re.compile(r"(Status:.*)")
    for match in pattern.findall(data):
        if match.split(":")[0].strip().find("Status") != -1:
            domain_status += match.split(":")[1].strip()
            domain_status += ";"

    pattern2 = re.compile(r"(Domain nameservers([\s\S]*?)Record maintained)")
    for match4 in pattern2.findall(data):
        for line in str(match4[0]).split("\n"):
            if line:
                if line.find("Domain nameservers") == -1 and line.find(
                        "Record maintained") == -1:
                    name_server += line.strip()
                    name_server += ";"

    domain_whois["domain_status"] = domain_status.strip(";")
    domain_whois["name_server"] = name_server.strip(";")

    return domain_whois


if __name__ == "__main__":
    # use demo
    w = WHOIS_info_extract_func()
    print w.get_whois_func("whois.jprs.jp")
    print w.get_whois_func("whois.cnnic.cn")
    print w.get_whois_func("just for test")
