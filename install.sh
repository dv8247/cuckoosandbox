#!/bin/bash

CUCKOO_ADMIN_PASSWORD=cuckoopass
CUCKOO_MYSQL_USERNAME=cuckoouser
CUCKOO_MYSQL_PASSWORD=cuckoopass
CUCKOO_MYSQL_DB=cuckoodb
CUCKOO_USER=cuckoo
CUCKOO_GROUP=cuckoo
MYSQL_ROOT_PASSWORD=password
SERVICE_USER=root
WEB_USER=www-data

### DO NOT EDIT BELOW THIS LINE ###
if [ "$(id -u)" != "0" ]; then
  echo "The install script should be run as root" 1>&2
  exit 1
fi

# Virtualization Software
# Despite heavily relying on VirtualBox in the past, Cuckoo has moved on being
# architecturally independent from the virtualization software. As you will see
# throughout this documentation, you’ll be able to define and write modules to
# support any software of your choice.
echo
echo "============================"
echo "    Installing Virtualbox   "
echo "============================"
echo
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | apt-key add -

VIRTUALBOX_REPO_FILE=/etc/apt/sources.list.d/virtualbox.list

cat > $VIRTUALBOX_REPO_FILE << EOF
deb http://download.virtualbox.org/virtualbox/debian jessie contrib
EOF

apt-get update && apt-get -y install dkms virtualbox-4.3

echo
echo "======================"
echo "    Creating Users    "
echo "======================"
echo
groupadd $CUCKOO_GROUP
useradd -G $VBOXUSER -g $CUCKOO_GROUP $CUCKOO_USER || true

# Cuckoo host components are completely written in Python, therefore make sure
# to have an appropriate version installed. For the current release Python 2.7
# is preferred.
echo
echo "====================================="
echo "    Installing Python Dependencies   "
echo "====================================="
echo
apt-get update && apt-get upgrade -y
apt-get install -y python python-dev python-pip python-gridfs git build-essential

# If you want to use the Django-based web interface,
# you’ll have to install MongoDB too:
echo
echo "=========================="
echo "    Installing MongoDB    "
echo "=========================="
echo
apt-get install -y mongodb

# If you want to use the serve the Django-based web interface,
# using Apache, you have to install libapache2-mod-wsgi.
echo
echo "================================"
echo "    Installing Apache Django    "
echo "================================"
echo
apt-get install -y libapache2-mod-wsgi uwsgi uwsgi-plugin-python uwsgi-plugins-all

# In order to properly function, Cuckoo requires SQLAlchemy and Python BSON to
# be installed
echo
echo "============================="
echo "    Installing SQLAlchemy    "
echo "============================="
echo
apt-get install -y python-sqlalchemy python-bson

# There are other optional dependencies that are mostly used by modules and
# utilities. The following libraries are not strictly required, but their
# installation is recommended

# Jinja2 (Highly Recommended): for rendering the HTML reports and web interface
echo
echo "========================="
echo "    Installing Jinja2    "
echo "========================="
echo
apt-get install -y python-jinja2

# Magic (Optional): for identifying files’ formats
# (otherwise use “file” command line utility)
echo
echo "========================"
echo "    Installing Magic    "
echo "========================"
echo
apt-get install -y python-magic

# Pymongo (Optional): for storing the results in a MongoDB database.
echo
echo "=========================="
echo "    Installing Pymongo    "
echo "=========================="
echo
pip install pymongo

# MySQL-Python (Optional): for storing the results in a MySQL database
echo
echo "==============================="
echo "    Installing MySQL-Python    "
echo "==============================="
echo
apt-get install -y python-mysqldb

# Bottlepy (Optional): for using the api.py or web.py utility (use release 0.10 or above).
echo
echo "==========================="
echo "    Installing Bottlepy    "
echo "==========================="
echo
apt-get install -y python-bottle

# Django (Optional): for using the web interface (use release 1.5 or above).
echo
echo "========================="
echo "    Installing Django    "
echo "========================="
echo
pip install Django==1.6.1

# Pefile (Optional): used for static analysis of PE32 binaries.
echo
echo "========================="
echo "    Installing Pefile    "
echo "========================="
echo
apt-get install -y python-pefile

# Install dedendencies for distributed cuckoo
echo
echo "====================================="
echo "    Installing Cuckoo pip modules    "
echo "====================================="
echo
pip install flask flask-restful flask-sqlalchemy requests alembic python-dateutil

# Dpkt (Highly Recommended): for extracting relevant information from PCAP files
echo
echo "======================="
echo "    Installing Dpkt    "
echo "======================="
echo
apt-get install -y python-dpkt

tar -zxvf dpkt-1.8.tar.gz && cd dpkt-1.8 && python setup.py install
cd .. && rm -fr dpkt-1.8

# Yara will have to be installed manually, so please refer to the website.
# Yara and Yara Python (Optional): for matching Yara signatures
# (use release 1.7.2 or above or the svn version).
echo
echo "======================="
echo "    Installing Yara    "
echo "======================="
echo
apt-get install -y libpcre3 libpcre3-dev libyara-dev

tar zxf v3.3.0.tar.gz && cd yara-3.3.0
./bootstrap.sh && ./configure
make && make install

cd yara-python
python setup.py build && python setup.py install
cd ../../ && rm -fr yara-3.3.0

# Pydeep will have to be installed manually, so please refer to the website.
# Pydeep (Optional): for calculating ssdeep fuzzy hash of f
echo
echo "========================="
echo "    Installing Pydeep    "
echo "========================="
echo
apt-get install -y unzip

tar zxf ssdeep-2.10.tar.gz && cd ssdeep-2.10
./configure && make && make check && make install
cd .. && rm -fr ssdeep-2.10

tar zxvf pydeep-0.2.tar.gz && cd pydeep-0.2
python setup.py build && python setup.py install
cd .. && rm -fr pydeep-0.2

# The release of this version coincides with the publication of The Art of
# Memory Forensics. It adds support for Windows 8, 8.1, 2012, and 2012 R2 memory
# dumps and Mac OS X Mavericks (up to 10.9.4). New plugins include the ability
# to extract cached Truecrypt passphrases and master keys from Windows and Linux
# memory dumps, investigate Mac user activity (such as pulling their contact
# database, calendar items, PGP encrypted mails, OTR Adium chat messages, etc),
# and analyze advanced Linux rootkit
echo
echo "============================="
echo "    Installing Volatility    "
echo "============================="
echo
# PyCrypto  - The Python Cryptography Toolkit
# PIL       - Python Imaging Library
# OpenPyxl  - Python library to read/write Excel 2007 xlsx/xlsm file
# Pytz      - Python library for timezone convers
apt-get install -y python-crypto python-imaging python-openpyxl python-tz ipython cmake

unzip distorm3.zip && cd distorm3 && python setup.py install
cd .. && rm -fr distorm3

apt-get -y install libdistorm64-1 && dpkg -i rekall-forensic_1.3.1_amd64.deb

tar xvfz libforensic1394-0.2.tar.gz && cd libforensic1394-0.2
mkdir build && cd build && cmake -G"Unix Makefiles" ../ && make && make install
cd ../../ && rm -fr libforensic1394-0.2

tar zxvf volatility-2.4.tar.gz && cd volatility-2.4 && python setup.py install
cd .. && rm -fr volatility-2.4

# MAEC Python bindings (Optional): used for MAEC reporting
# (use a release >=4.0, but <4.1).
echo
echo "======================="
echo "    Installing MAEC    "
echo "======================="
echo
# Chardet (Optional): used for detecting string encoding
apt-get -y install libxml2-dev libxslt-dev python-chardet

tar xvfz cybox-2.0.1.4.tar.gz && cd cybox-2.0.1.4 && python setup.py install
cd .. && rm -fr cybox-2.0.1.4

tar xvfz maec-4.0.1.0.tar.gz && cd maec-4.0.1.0 && python setup.py install
cd .. && rm -fr maec-4.0.1.0

# In order to dump the network activity performed by the malware during execution,
# you’ll need a network sniffer properly configured to capture the traffic and
# dump it to a file.
# By default Cuckoo adopts tcpdump, the prominent open source solutio
# Tcpdump requires root privileges, but since you don’t want Cuckoo to run as
# root you’ll have to set specific Linux capabilities to the binary:
echo
echo "=========================="
echo "    Installing tcpdump    "
echo "=========================="
echo
apt-get -y install tcpdump libcap2-bin

setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# You either can run Cuckoo from your own user or create a new one dedicated just
# to your sandbox setup. Make sure that the user that runs Cuckoo is the same user
# that you will use to create and run the virtual machines, otherwise Cuckoo won’t
# be able to identify and launch them.
echo
echo "================================"
echo "    Installing Cuckoosandbox    "
echo "================================"
echo
tar zxvf cuckoo_1.2.0.tar.gz -C /opt/
mkdir /opt/cuckoo/tmp

cat << '__EOF__' > /opt/cuckoo/web/web/local_settings.py
LOCAL_SETTINGS = True
from settings import *

CUCKOO_PATH = "/opt/cuckoo"
CUCKOO_FILE_UPLOAD_TEMP_DIR = "/opt/cuckoo/tmp"
MAX_UPLOAD_SIZE = 26214400
# SECRET_KEY = "YOUR_RANDOM_KEY"
TIME_ZONE = "America/New_York"
LANGUAGE_CODE = "en-us"

ADMINS = (
    # ("Your Name", "your_email@example.com"),
)

MANAGERS = ADMINS
DEBUG = True
ALLOWED_HOSTS = ["*"]
__EOF__

cat << '__EOF__' > /opt/cuckoo/web/web/wsgi.py
import os,sys

sys.path.append('/opt/cuckoo')
sys.path.append('/opt/cuckoo/web')
os.chdir('/opt/cuckoo/web/')

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

__EOF__

# Packer is a tool for creating identical machine images for multiple platforms
# from a single source configuration
echo
echo "========================="
echo "    Installing Packer    "
echo "========================="
echo
unzip -d /usr/local/bin packer_0.8.1_linux_amd64.zip

# Vagrant is a tool to create and configure lightweight, reproducible, and
# portable development environments.
echo
echo "=========================="
echo "    Installing Vagrant    "
echo "=========================="
echo
dpkg -i vagrant_1.7.2_x86_64.deb

# This repository contains templates for Windows that can create Vagrant boxes using Packer.
echo
echo "===================================="
echo "    Installing Windows Templates    "
echo "===================================="
echo
[ -d /home/cuckoo/boxcutter ] || git https://github.com/boxcutter/windows.git /home/cuckoo/boxcutter

# Install Virtualhost
echo
echo "==========================="
echo "    Configuring Apache     "
echo "==========================="
echo
apt-get install -y libapache2-mod-gnutls

cat << '__EOF__' > /etc/apache2/sites-available/cuckoo_web
<IfModule mod_gnutls.c>
    NameVirtualHost *:8080
    Listen 8080
    <VirtualHost *:8080>
		ServerAdmin webmaster@localhost
		ServerName web.cuckoo.net.local
		WSGIDaemonProcess web.cuckoo.net.local user=cuckoo group=cuckoo processes=1 threads=5 python-path=/opt/cuckoo/web:/opt/cuckoo/web/web:/opt/cuckoo/lib
		WSGIProcessGroup web.cuckoo.net.local
		WSGIScriptAlias / /opt/cuckoo/web/web/wsgi.py
		<Directory /opt/cuckoo/web/web>
			WSGIApplicationGroup %{GLOBAL}
			AllowOverride All
			Order deny,allow
			Allow from all
		</Directory>

		Alias /static /opt/cuckoo/web/static
		ErrorLog ${APACHE_LOG_DIR}/cuckoo_web_ssl_error.log

		# Possible values include: debug, info, notice, warn, error, crit, alert, emerg.
		LogLevel warn
		CustomLog ${APACHE_LOG_DIR}/cuckoo_web_ssl_access.log combined

		GnuTLSEnable on
		GnuTLSPriorities SECURE256:-VERS-TLS1.0
		GnuTLSCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
		GnuTLSKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

		BrowserMatch "MSIE [2-6]" \
		nokeepalive ssl-unclean-shutdown \
		downgrade-1.0 force-response-1.0
		# MSIE 7 and newer should be able to use keepalive
		BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown
    </VirtualHost>
</IfModule>
__EOF__

a2enmod gnutls

# Disable all Apache default sites, however they're called
a2dissite default || true
a2dissite default-ssl || true
a2dissite default-tls || true
a2ensite cuckoo_web && service apache2 restart

echo
echo "========================================"
echo "    Installing Ruby Version Manager     "
echo "========================================"
echo
apt-get install -y curl
gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable --ruby

echo
echo "========================"
echo "    Installing Chef     "
echo "========================"
echo
source /usr/local/rvm/scripts/rvm
gem install chef --no-document

[ -d /home/cuckoo/chef-repo ] || git clone git://github.com/chef/chef-repo.git /home/cuckoo/chef-repo

rm -fr /home/cuckoo/chef-repo/.git && git init /home/cuckoo/chef-repo
cd /home/cuckoo/chef-repo && git add . && git commit -m 'initial commit'

mkdir /home/cuckoo/.chef

cat << '__EOF__' > /home/cuckoo/.chef/knife.rb
current_dir = File.dirname(__FILE__)
user_email  = `git config --get user.email`
user_name   = `git config --get user.name`
home_dir    = ENV['HOME'] || ENV['HOMEDRIVE']
cache_options(             :path => "#{ENV['HOME']}/.chef/checksums" )
cookbook_copyright         "#{user_name}"
cookbook_email             "#{user_email}"
cookbook_path              ["./cookbooks", ".", "..", "#{ENV['HOME']}/chef-repo/cookbooks"]
cookbook_license           "apachev2"
knife[:editor] =           "/usr/bin/vim"
knife_override =           "#{home_dir}/.chef/knife_override.rb"
node_name                  ( ENV['USER'] || ENV['USERNAME'] ).downcase
syntax_check_cache_path    "#{ENV['HOME']}/.chef/syntax_check_cache"
verify_api_cert            false
versioned_cookbooks        false
log_level                  :info
log_location               STDOUT
__EOF__

chown -R cuckoo.cuckoo /home/cuckoo
chown -R cuckoo.cuckoo /opt/cuckoo

echo
echo "======================================"
echo "    Done Installing Cuckoosandbox     "
echo "======================================"
echo
