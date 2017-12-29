# getWeblogicPorts
扫描端口，生成扫描文件
nmap -Pn -n -sV --min-hostgroup 32 --min-parallelism 256 -p1000-9999 -O -iL iplist.txt -oX iplist.xml
