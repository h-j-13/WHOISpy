
WHOISpy
 ---------------------- 
![](https://img.shields.io/badge/Python-2.7.15-blue.svg) ![](https://img.shields.io/badge/license-WTFPL-blue.svg) ![](https://img.shields.io/github/repo-size/h-j-13/WHOISpy.svg) ![](https://img.shields.io/bitbucket/issues-raw/h-j-13/WHOISpy.svg) ![](https://img.shields.io/github/stars/h-j-13/WHOISpy.svg?style=social) 

WHOISpy是一个Python编写的基于RFC3912的智能WHOIS客户端,你可以通过它轻松的获取并提取域名WHOIS关键信息  

## 快速上手
WHOISpy是一个Python编写的基于RFC3912的智能WHOIS客户端,如果你不太熟悉WHOIS这个概念,请参考[wiki-WHOIS](https://zh.wikipedia.org/wiki/WHOIS)和[部分相关文献](https://github.com/h-j-13/WHOIS-theory.zh-cn).简而言之,域名WHOIS数据相当于一个域名的"身份证".

### 如何使用?
WHOISpy无需预先安装任何第三方库,直接克隆仓库至本地当作一个PythonPackage使用即可
示例代码如下:
```python
>>>from WHOISpy.WHOIS import WHOIS  
>>>WHOIS("github.com")  
{  
 "domain": "baidu.com", 
 "tld": "com", 
 "top_whois_server": "whois.verisign-grs.com", 
 "sec_whois_server": "whois.markmonitor.com", 
 "sponsoring_registrar": "MarkMonitor, Inc.",
  ...
}
```

## 特性

1. 支持输入url及FQDN,自动解析出域名
2. 支持多达1444个顶级域域名WHOIS信息查询 
3. 支持SOCKS4,5代理来进行WHOIS信息查询 
4. 支持使用转发WHOIS服务器
5. WHOIS信息关键字段解析,json格式化
6. WHOIS时间字符串标准化

### 如何使用这些特性
请参考WHOIS.py中的WHOIS函数
```python
def WHOIS(raw_domain,  
  whois_server="",  
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
    """  
  获取域名WHOIS信息并智能解析关键字段  
  :param raw_domain: 				原始url  
  :param whois_server: 				指定的WHOIS服务器  
  :param format_time: 				标准化时间  
  :param format_domain_status: 		        标准化域名状态标记  
  :param list_name_server: 			列表格式记录域名NS服务器标记  
  :param socket_time_out:                       socket 连接超时时间  
  :param socket_retry_time:                     socket 连接最大重试次数  
  :param use_sock_proxy: 			是否使用socks代理  
  :param proxy_type: 				代理的类型(仅支持 SOCKS4 , SOCKS5 不支持 HTTP,HTTPS 代理)  
  :param proxy_ip: 			        代理ip  
  :param proxy_port: 				代理端口  
  :param proxy_username: 			代理用户名  
  :param proxy_password: 			代理密码  
  :param use_relay_WHOIS_server: 	        是否使用转发服务器查询标记  
  :return:                                      经过关键字段解析及标准化的WHOIS信息字典  
 """
 
 ...
```


### 目标
1. 100%的域名WHOIS查询支持 (目前支持1444个顶级域,共1517个)
2. 100%的域名WHOIS查询解析完整 (暂无覆盖数据)

## 原理
WHOISpy基于 [RFC 3912](https://tools.ietf.org/html/rfc3912) 协议所规定的域名WHOIS查询流程所编写
基本流程如下:

1. 获取输入,解析域名
2. 根据域名顶级域选择对应的WHOIS服务器
3. 向相应的WHOIS服务器发送查询请求       
	3.1 如果改顶级域存在二级WHOIS服务器,则在通讯结果中寻找二级WHOIS服务器地址        
	3.2 向找到的二级WHOIS服务器发出查询请求  
4. 整合结果,根据顶级域选择不同的模板对WHOIS原始数据进行解析,提取关键字
                               
## 依赖环境  
安装、使用WHOISpy时**不需要**提前安装任何第三方库.     
为了支持socks代理,使用了[Anorov](https://github.com/Anorov) 的 **[PySocks](https://github.com/Anorov/PySocks)**,为了方便使用已将代码复制到本repo内.

如果希望获取**更好的时间处理能力**,请安装pytz与datetuil这两个第三方库
```shell
pip install pytz
pip install python-dateutil
```  
  
## 数据

### WHOIS记录
查询到的WHOIS记录被自动解析为一个python字典或者json格式,各字段含义如下
```python
WHOIS_RECORD = {  
  "domain": "", # 域名  
  "tld": "", # 顶级域  
  "flag": "", # 状态标记  
  "domain_status": "", # 域名状态  
  "sponsoring_registrar": "", # 注册商  
  "top_whois_server": "", # 顶级域名服务器  
  "sec_whois_server": "", # 二级域名服务器  
  "reg_name": "", # 注册姓名  
  "reg_phone": "", # 注册电话  
  "reg_email": "", # 注册email  
  "org_name": "", # 注册公司名称  
  "creation_date": "", # 创建时间  
  "expiration_date": "", # 到期时间  
  "updated_date": "", # 更新时间  
  "details": "", # 原始信息(一级WHOIS信息 + 二级WHOIS信息)  
  "top_whois_detail": "", # 一级WHOIS信息  
  "sec_whois_detail": "", # 二级WHOIS信息  
  "name_server": "", # 域名服务器  
}
```
### WHOIS获取异常
因为网络原因,查询域名WHOIS过程中不可避免的会出现各种异常,下面是各WHOIS异常标记含义

| WHOIS异常标记 | 值 | 含义 |
| ------ | ------ | ------ |
| FLAG_CANT_DEAL | 0 | 不能处理   |
| FLAG_OK | 1 | 正常   |
| FLAG_NO_WHOIS_ADDR | -1 | 未找到WHOIS服务器   |
| FLAG_TOP_WHOIS_FAILED | -2 | 一级WHOIS获取网络错误 |
| FLAG_NO_SEC_WHOI_ADDR | -3 |  未找到二级WHOIS服务器   |
| FLAG_SEC_WHOIS_FAILED | -4 | 二级WHOIS获取网络错误   |
| FLAG_EMPTY_WHOIS_INFO | -5 |  WHOIS信息为空   |
| FLAG_INFO_EXTRACT_FAILED | -6 | WHOIS关键信息解析失败 |


### 域名WHOIS状态值映射
为了数据存储、查询方便,WHOISpy默认把域名状态值转化为数字,其映射关系可详见 [WHOISpy/WHOIS_info_extract.py](https://github.com/h-j-13/WHOISpy/blob/master/WHOISpy/WHOIS_info_extract.py#L64-L102)

### 关键数据来源

1. 常见域名后缀 - [public_suffix_list.dat](https://github.com/h-j-13/WHOISpy/blob/cb3a828f0606aca60991fe4a35f505ddc9f6f5ca/WHOISpy/data/public_suffix_list.dat)  \[ 来自 https://publicsuffix.org/list/ \]
2. 域名WHOIS服务器与顶级域映射关系 - [WHOIS_server_list.dat](https://github.com/h-j-13/WHOISpy/blob/cb3a828f0606aca60991fe4a35f505ddc9f6f5ca/WHOISpy/data/WHOIS_server_list.dat) \[ 主要基于[IANA](http://www.iana.org/domains/root/db)页面数据 \]
3. WHOIS服务器请求格式与默认字符 - [WHOIS_server_list.dat](https://github.com/h-j-13/WHOISpy/blob/cb3a828f0606aca60991fe4a35f505ddc9f6f5ca/WHOISpy/data/WHOIS_server_list.dat) \[ 来自 [rfc1036](https://github.com/rfc1036) 的 **[whois](https://github.com/rfc1036/whois)**\]

## License  
WTFPL License