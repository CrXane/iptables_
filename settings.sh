echo ### 1: Drop invalid packets ### 
sudo iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP  

echo ### 2: Drop TCP packets that are new and are not SYN ### 
sudo iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 
 
echo ### 3: Drop SYN packets with suspicious MSS value ### 
sudo iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  

echo ### 4: Block packets with bogus TCP flags ### 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP  

echo ### 5: Block spoofed packets ### 
sudo iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  

echo ### 6: Drop ICMP (you usually don't need this protocol) ### 
sudo iptables -t mangle -A PREROUTING -p icmp -j DROP  

echo ### 7: Drop fragments in all chains ### 
sudo iptables -t mangle -A PREROUTING -f -j DROP  

echo ### 8: Limit connections per source IP ### 
sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  

echo ### 9: Limit RST packets ### 
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  

echo ### 10: Limit new TCP connections per second per source IP ### 
sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 

echo ### 11: SYNPROXY rules that help mitigate SYN floods that bypass our other rules ###
sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  
sudo iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack 
sudo iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

echo ### 12: Limit the ammount of concurrent connections from the same IP address ###
sudo iptables -I INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --set
sudo iptables -I INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables-save >/etc/iptables.up.rules

echo ### SSH brute-force protection ### 
sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

echo ### Protection against port scanning ### 
sudo iptables -N port-scanning 
sudo iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
sudo iptables -A port-scanning -j DROP

echo ### Check if being attacked ###
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n 

echo ### DROP IP ###
echo iptables -A INPUT -s xxx.xxx.xxx.xxx -j DROP

echo ### Save bans on restart ###
iptables-save > /etc/iptables.up.rules
iptables-restore < /etc/iptables.up.rules
