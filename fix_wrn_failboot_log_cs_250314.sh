#!/bin/bash

# Create the file if it does not exist and clear the contents of /etc/logrotate.d/rsyslog
if [ ! -f /etc/logrotate.d/rsyslog ]; then
    touch /etc/logrotate.d/rsyslog
    chown root:root /etc/logrotate.d/rsyslog
else
    > /etc/logrotate.d/rsyslog
    chown root:root /etc/logrotate.d/rsyslog
fi

cat <<EOL > /etc/logrotate.d/rsyslog
su root syslog
/var/log/kern.log
/var/log/syslog
{
    rotate 2
    daily
    size 350M
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOL

# Insert the new line before the specified pattern in /etc/rsyslog.d/50-default.conf
if ! grep -q '\$outchannel mysyslog,/var/log/syslog,367001600' /etc/rsyslog.d/50-default.conf; then
    sed -i '/\*\.\*;auth,authpriv\.none/i \$outchannel mysyslog,/var/log/syslog,367001600' /etc/rsyslog.d/50-default.conf
fi
# Replace the specified pattern with the new line in /etc/rsyslog.d/50-default.conf
sed -i "s/\*\.\*;auth,authpriv\.none\s*\-\/var\/log\/syslog/\*\.\*;auth,authpriv\.none          :omfile:\$mysyslog/" /etc/rsyslog.d/50-default.conf

# Change ownership of /etc and /system folders to root
chown -R root:root /etc
chown -R root:root /system

sudo logrotate -f /etc/logrotate.conf
sudo journalctl --vacuum-size=1G
# Check if there are any files larger than 100MB in /var/log
find /var/log -type f -size +100M -exec rm -f {} \;

sudo systemctl enable logrotate.service
sudo systemctl restart logrotate.service
sync

if find /var/log -type f -size +100M | grep -q .; then
    echo "fail to remove wrn bug"
else
    echo "success to remove wrn bug"
fi

