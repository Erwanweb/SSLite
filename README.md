# SSLite
Security system LITE



install :

cd ~/domoticz/plugins

mkdir SSLite

sudo apt-get update

sudo apt-get install git

git clone https://github.com/Erwanweb/SSLite.git SSLite

cd SSLite

sudo chmod +x plugin.py

sudo /etc/init.d/domoticz.sh restart

Upgrade :

cd ~/domoticz/plugins/SSLite

git reset --hard && git pull --force

sudo /etc/init.d/domoticz.sh restart
