#!/bin/bash
#
#-----------------------------------------#
###Welcome to the squirrelmail setup script. Any variables that may need to be adjusted should be changed in the designated "variables" section in the main script, super.sh.
#-----------------------------------------#
echo "@@ Doing squirrelmail ${1:-}";

# allow "--preinstall" to just preinstall packages.
# follow with "--config" later on to actually install them
if [ "${1:-}" != "--config}"; then

    sudo $package_manager install php -y || exit $?

    sudo wget "http://downloads.sourceforge.net/project/squirrelmail/stable/$squirrel_mail_v/squirrelmail-webmail-$squirrel_mail_v.zip" || exit $?

    sudo mkdir -p /usr/local/squirrelmail || exit $?

    sudo unzip squirrelmail-webmail-1.4.22.zip -d /usr/local/squirrelmail || exit $?

    sudo mv "/usr/local/squirrelmail/squirrelmail-webmail-$squirrel_mail_v/" "/usr/local/squirrelmail/www" || exit $?

    sudo chown -R apache: /usr/local/squirrelmail/ || exit $?

    sudo cp -p /usr/local/squirrelmail/www/config/config_default.php /usr/local/squirrelmail/www/config/config.php || exit $?

    if [ "${1:-}" = "--preinstall" ]; then exit 0; fi;
fi

squirrel_settings=(domain data_dir attachment_dir smtpServerAddress imapServerAddress)
sdir="/usr/local/squirrelmail/www/config/config.php"

for var in ${squirrel_settings[*]}; do
    temp="$(sudo grep -n ^\$$var $sdir | grep -o '[0-9]*')"
    if [ "$temp" != "" ]; then
        echo "Updating variable..." 
        sudo sed -i "${temp}d" $sdir
    fi
    echo "Writing variable..."
    echo "\$$var = ${!var}" | sudo tee -a "$sdir"

done
