#!/bin/bash # Todo: sa-update via cron.
#-----------------------------------------#
###Welcome to the main setup script. Here you will be able to adjust crucial variables
# in the "Variables" section for each section as well as see which files executed and when.
#-----------------------------------------#
#   ___         _    _                
#  / _ \  _ __ | |_ (_) ___  _ _   ___
# | (_) || '_ \|  _|| |/ _ \| ' \ (_-<
#  \___/ | .__/ \__||_|\___/|_||_|/__/
#        |_|                          
#-----------------------------------------#
opt_dry=false;		#true for test mode
opt_xearly=false;	#true for test mode
opt_log=false;		#true to write log file
opt_mode=".";		#. for normal, preinstall, config
trouble=false;		#true for fatal exit
while [ $# -ge 1 ] && [[ "$1" == -* ]]; do
    opt="$1";
    case "$opt" in
      (--log=*)	     opt_log=true;;
      (--preinstall) opt_mode="$1";;
      (--)	     break;;

      # internal unpublished/unsupported options 
      (---dry) 	     opt_dry=true;;
      (---xearly)    opt_xearly=true;;

      (*)	     echo >&2 "Unknown option $opt";
      		     trouble=true;;
    esac;
done
unset opt;

$opt_dry && safe="echo DRY..." || safe="";

#-----------------------------------------#
#  _                      _             
# | |    ___  __ _  __ _ (_) _ _   __ _ 
# | |__ / _ \/ _` |/ _` || || ' \ / _` |
# |____|\___/\__, |\__, ||_||_||_|\__, |
#            |___/ |___/          |___/ 
#-----------------------------------------#
if $opt_log;  then
    set -o pipefail;
    log="../super-$(date '+%Y%m%d.%H%M').log";
    	# write to .. so grepping local source does not
	# come up with false hits in log in ".".
    $0 "$@" | cat -n | tee "$log";
    exit $?;
fi
#-----------------------------------------#
#                 _       _     _  
#/\   /\__ _ _ __(_) __ _| |__ | | ___  ___ 
#\ \ / / _` | '__| |/ _` | '_ \| |/ _ \/ __|
# \ V / (_| | |  | | (_| | |_) | |  __/\__ \
#  \_/ \__,_|_|  |_|\__,_|_.__/|_|\___||___/
#-----------------------------------------#
##Export Variables so that child processes can view them.
set -a
#-----------------------------------------#
#Postfix Settings
#-----------------------------------------#

##Required Substitutions:
virtual_mailbox_domains="example.com" #Include all domains here, format: "example.com another.com"
default_password="admin"
##

#  NOTE: rather than changing local files put overrides into optional super.local file
[ -s ./super.local ] && ./source super.local;
#  preliminary read of above local defs.. final read follows.

#Additional Subsitutions
mydomain="$(echo $virtual_mailbox_domains | awk '{print $1}')" #ONLY FIRST DOMAIN USED FOR HTTPS CERT
myhostname="mail.$mydomain"
myorigin="$mydomain"
inet_interfaces="all"
mydestination="localhost"
mynetworks="127.0.0.0/8"

##Additions *Possible Substitutions, be wary of direct transer
###Certificates

key_file=server.pem
cert_file=server.pem
smtpd_tls_key_file="/etc/pki/tls/private/$key_file"
smtpd_tls_cert_file="/etc/pki/tls/certs/$cert_file"

###Sasl Authentication

smtpd_recipient_restrictions="permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"
smtpd_sasl_auth_enable=yes
broken_sasl_auth_clients=yes
smtpd_sasl_type=dovecot
smtpd_sasl_path=private/auth
smtpd_sasl_security_options=noanonymous

###Mailbox mappings, including transports and aliases

virtual_uid_maps=static:200
virtual_gid_maps=static:12
transport_maps=pgsql:/etc/postfix/pgsql/transport.cf
virtual_mailbox_base=/mnt/vmail
virtual_mailbox_maps=pgsql:/etc/postfix/pgsql/mailboxes.cf
virtual_transport=lmtp:unix:private/dovecot-lmtp
virtual_alias_maps=pgsql:/etc/postfix/pgsql/pgsql-aliases.cf
local_recipient_maps=
message_size_limit=0

###Taking Care of SPAM and VIRUSES:                                             

# historic, defunct, rpmforge
rpmforge_v=0.5.2-2
rpmforge_url=http://apt.sw.be/redhat/el6/en/x86_64/rpmforge/RPMS/rpmforge-release-$rpmforge_v.el6.rf.x86_64.rpm

# 2016-08 try repoforge instead
rpmforge_v="";		#don't require under epel-testingepel-testing
rpmforge_url=http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-$rpmforge_v.el6.rf.x86_64.rpm

content_filter=smtp-amavis:[127.0.0.1]:10024

###Master.cf Configurations

#-----------------------------------------#
#Dovecot Settings
#-----------------------------------------#

##Main Conf

protocols="imap lmtp sieve"

##Main conf / Conf.d

ssl=required
ssl_cert="<$smtpd_tls_cert_file"
ssl_key="<$smtpd_tls_key_file"
first_valid_uid=200
mail_uid=200
mail_gid=12
disable_plaintext_auth=yes
auth_mechanisms="plain login"
auth_debug_passwords=yes                                                      
mail_home=/mnt/vmail/%d/%n
mail_location="maildir:~"
mail_debug=yes
lda_mailbox_autocreate=yes
lda_mailbox_autosubscribe=yes

special_sql_file="auth-sql.conf.ext.sp"


#-----------------------------------------#
#Postgresql Settings
#-----------------------------------------#
database_pass=$default_password
mailreader_user=mailreader
dbname=mail
path_to_hba="/var/lib/pgsql9/data/pg_hba.conf"
path_to_pgsql=pgsql
init_script="/etc/rc.d/init.d/postgresql"
var_store="/etc/sysconfig/pgsql/postgresql"
#PGDATA=/mnt/vmail/db
#PGLOG=/mnt/vmail/pgstartup.log

#-----------------------------------------#
#Security & Spam Settings
#-----------------------------------------#
amavis_conf="/etc/amavisd.conf"
amavis_init="/etc/init.d/amavisd"
amavis_pid="/var/amavis/amavisd.pid"
spamassassin_conf="/etc/mail/spamassassin/local.cf" 
MYHOME="/var/amavis"
undecipherable_subject_tag=""
sa_spam_subject_tag=""
#Always include spam score headers:
sa_tag_level_deflt="-9999"
#Note: Amavis ignores required_score and instead uses sa_tag2_level_deflt:
sa_tag2_level_deflt=5
required_score=5
#Disable virus scanning.  (Companies with Windows clients may want to re-enable virus scanning.  Requires more AWS resources at high volume):
#bypass_virus_checks_maps = (1);
required_hits=5
report_safe=0
rewrite_header=""

default_sieve="/etc/dovecot/sieve/default.sieve"

#-----------------------------------------#
#Httpd ssl
#-----------------------------------------#

httpd_conf="/etc/httpd/conf/httpd.conf"
httpd_ssl_conf="/etc/httpd/conf.d/ssl.conf"
SSLCertificateFile=$smtpd_tls_cert_file
SSLCertificateKeyFile=$smtpd_tls_key_file
SSLProtocol="all -SSLv2 -SSLv3"

#-----------------------------------------#
#Squirrelmail
#-----------------------------------------#

squirrel_mail_v="1.4.22"
domain="'$mydomain';"
data_dir="'/usr/local/squirrelmail/www/data/';"
attachment_dir="'/usr/local/squirrelmail/www/attach/';"
smtpServerAddress="'localhost';"
imapServerAddress="'localhost';"
#-----------------------------------------#
#   ___  __      ___     _        _ _     
#  /___\/ _\    /   \___| |_ __ _(_) |___ 
# //  //\ \    / /\ / _ \ __/ _` | | / __|
#/ \_// _\ \  / /_//  __/ || (_| | | \__ \
#\___/  \__/ /___,' \___|\__\__,_|_|_|___/                        
#-----------------------------------------#
if [ "$(which yum)" != "" ]; then
    echo "OS uses Yum"
    package_manager="yum"
    network_file="/etc/sysconfig/network"
    postfix_dir="/etc/postfix/"
    postfix_main="main.cf"
    postfix_master="master.cf"
    dovecot_dir="/etc/dovecot/"
    dovecot_confd="conf.d/"
    dovecot_main="dovecot.conf"

elif [ "$(which apt-get)" != "" ]; then
    echo "OS uses Apt-get"
    package_manager="apt-get"
fi

#assure appropriate repositories enabled
if [ ! -w / ]; then
    echo "NOT ROOT: developer testing in safe mode"
    echo "User is not root. use sudo ./super.sh";
fi

# suspect following "if rpmforge_v" can go away... but not quite yet
if [ "$rpmforge_v" == "" ]; then
    #pulling amavisd-new from EPEL repository... we hope
    if ! repoquery -i amavisd-new >/dev/null 2>&1; then
	echo >&2 "ERROR: amavisd-new NOT available in repositories";
	echo >&2 "Be sure in /etc/yum.repos.d/epel*.repo the";
	echo >&2 "[epel] and [epel-testing] sections have enabled=1";
	echo >&2 "You may want to set these OFF after system working.";
	trouble=true;
    fi
fi

#-----------------------------------------#
#  _                    _  __   __              
# | |    ___  __  __ _ | | \ \ / /__ _  _ _  ___
# | |__ / _ \/ _|/ _` || |  \ V // _` || '_|(_-<
# |____|\___/\__|\__,_||_|   \_/ \__,_||_|  /__/
#                                               
#-----------------------------------------#
if [ -s ./super.local ]; then
    #final, more fussy, overrides of ALL above variables
    source ./super.local || exit $?;	#die on trouble in file
fi
#-----------------------------------------#
# __           _       _   
#/ _\ ___ _ __(_)_ __ | |_ 
#\ \ / __| '__| | '_ \| __|
#_\ \ (__| |  | | |_) | |_ 
#\__/\___|_|  |_| .__/ \__|
#               |_| 
#-----------------------------------------#

$trouble && exit 23;

echo "Starting main setup"

#Sub-script run order is final and should not be adjusted. 
# # In addition, subscripts should ONLY BE LAUNCHED FROM super.sh as
#   there are many variable dependencies. 
# # Comment sub-scripts out if you don't want to run them again, 
#   but only do so after running everything at least once.
install_list=( 
	postfix.sh
	dovecot.sh 
	pgsql.sh
	amavis.sh 
	apache.sh
	crontab.sh
	"squirrelmail.sh=-d /usr/local/squirrelmail/www"
	    );
function do_script
{
    typeset il="$1"; shift;		#get simple name
    typeset sh="${il%%=*}";		#script
    typeset t="${il#*.sh}";		#test, with leading =
    if [[ "$t" == "=-"* ]]; then
    	#test conditional present... make it
	if eval "[ ${t#=} ]"; then 
	    echo "@@skip $sh";
	    continue;
	fi
    fi
    echo "@@doing $sh";
    ./$sh "$@";
    echo "@@done $sh";

}
function do_list
{
    for il in "${install_list[@]}"; do
	${safe}do_script "$il" "$@"
	case "$il" in
	  (postfix.sh)
	    status="$(ps ax | grep -v grep | grep postfix)"

	    if [ "$status" = "" ]; then 
		echo "Postfix failed to start... stopping ${0##*/} script."
		${safe}exit 1
	    else
		echo "Postfix up and running"
	    fi
	    ;;
	esac
    done
}

if ! $opt_dry; then
    # root user... update packages 
    sudo $package_manager update -y

    sudo ./perl-find-replace "$(grep HOSTNAME $network_file)" "HOSTNAME=\"$myhostname\"" $network_file 

    #Add a mail group and mailreader user
    sudo groupadd -g 12 mail
    sudo useradd -g mail -u 200 -d /mnt/vmail -s /sbin/nologin mailreader
fi

do_list_args=();	#suppose standard install
if [ "$opt_mode" = "--preinstall" ]; then
    # --preinstall -- likely developer testing things
    do_list "--preinstall" || exit $?;
    do_list_args=( "--config" );  #skip --preinstall
fi
if ${safe}false; then
    # dry mode not supported beyond this point
    echo "DRY MODE EXIT";
    exit 0;
fi

if $opt_xearly; then
    echo EARLY EXIT >&2; 
    exit 99;
fi

do_list "${do_list_args[@]}";

sudo service dovecot restart
sudo service postfix restart

echo "

The amavisd service may fail to start the first time... this is okay. If the mail setup isn't working, just run the setup script again, and the amavisd service should start correctly. Or to start the service yourself; service amavisd start.
"

sudo service amavisd start

status="$(ps ax | grep -v grep | grep httpd)"

if [ "$status" = "" ]; then 
    echo "Starting Apache"
    sudo service httpd start
else
    echo "Restarting Apache"
    sudo service httpd restart
fi

sudo chkconfig postfix on
sudo chkconfig dovecot on
sudo chkconfig postgresql on
sudo chkconfig amavisd on
sudo chkconfig spamassassin on
sudo chkconfig httpd on

sudo chmod 700 super.sh
sudo chmod -R 600 /etc/postfix/pgsql/
sudo chmod 755 /etc/postfix/pgsql/
sudo chown -R mailreader:root /etc/postfix/pgsql/
sudo chown root:root /etc/postfix/pgsql/

echo "Script permission has been highly elevated because it contains the default plain-text password. To run super.sh again you will need to become root, or change the file's permissions. -> sudo chmod 666 super.sh" 

echo "The setup is finished!"
