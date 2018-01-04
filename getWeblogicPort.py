#!/usr/bin/evn python
# coding:utf-8

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import sys
import getopt

if __name__ == "__main__":
    msg = '''
Usage: python getipport.py -x nmap-output.xml
'''
    if len(sys.argv) < 3:
        print msg
        sys.exit(-1)
    try:
        options, args = getopt.getopt(sys.argv[1:], "x:")
        xml_filename = ''
        for opt, arg in options:
            if opt == '-x':
                xml_filename = arg
    except Exception, e:
        print msg
        exit(-3)

    fh = file(xml_filename+'.result.txt', 'w')

    try:
        tree = ET.parse(xml_filename)  # 打开xml文档
        root = tree.getroot()  # 获得root节点
    except Exception, e:
        print "Error:cannot parse file:.xml."
        fh.close()
        sys.exit(-2)
    for host in root.findall('host'):  # 找到root节点下的所有host节点
        try:
            addr = host.find('address').get('addr')  # 子节点下节点address的值
            state = host.find('status').get('state')  # 子节点下属性name的值
            if state != 'up':
                continue
            ports = host.find('ports')    # 找到host节点下的所有ports节点
            oslist = host.find('os')
            os_macth_list = oslist.findall('osmatch')
        except Exception, e:
            continue
        
        print 'find '+addr 
        if len(os_macth_list) == 0:
            os = 'unknown'
        else:
            first_os_match = os_macth_list[0].get('name').lower()   #取第一个最大可能性的OS
            if (first_os_match.find('linux') >= 0 ):
        	    os = 'linux  '
            elif  (first_os_match.find('windows') >= 0 ):
                os = 'windows'
            else:
        	    os = 'unknown'
        weblogic_found = False;
        for port in ports.findall('port'):   # 找到ports节点下的所有port节点
            try:
                p = port.get('portid')
                pstate = port.find('state').get('state')
                service_name = port.find('service').get('name')
                service_product =  port.find('service').get('product')
            except Exception, e:
                continue
            if pstate != 'open':
                continue
            if  (service_name != 'http'):
            	continue
            if  (isinstance(service_product,str) and (service_product.find('WebLogic') >= 0  )):
                weblogic_found = True  
            else:
            	continue
            print addr+' '+p+' '+service_product;
            fh.write(os+' '+addr + ' ' + p +'\n')

    fh.close()
