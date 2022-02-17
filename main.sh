#!/bin/bash

# secure log file
#SECURE_FILE="/var/log/secure"
SECURE_FILE="secure"
# firewall rules
IP_TABLES="/usr/sbin/iptables"
# connection type
CONNECTION="ssh"
# error message
ERROR_MSG="Failed password"

# number of attempts before blocking the IP
MAX_ATTEMPTS="$1"
# time limit for blocking IP (in minutes)
TIME_LIMIT="$2"

# filters the secure log file
filter_lines()
{
  # search for lines that contain 'ssh' and 'Failed password'
  cat "$SECURE_FILE" | grep "$CONNECTION" | grep "$ERROR_MSG"
}

# format the filtered secure log file
read_file()
{
  # (current time - time limit)
  expiration_time=`date +%s -d"$TIME_LIMIT minutes ago"`

  # read each line from filtered secure log file
  filter_lines | while read line;
  do
    # convert line to array
    line_arr=($line)

    # connection type
    connection=${line_arr[4]:0:3}
    # IP address
    ip_addr=${line_arr[10]}
    # attempt time in epoch time
    attempt_time=`date +%s -d"${line_arr[0]} ${line_arr[1]} ${line_arr[2]}"`

    # -ge   greater than or equal to
    # -gt   greater than
    # if (attempt time >= expiration time)
    if [ $attempt_time -ge $expiration_time ]
    then
      echo "${ip_addr}" "${connection}"
    fi
  done
}

# count the number of duplicate lines in the filtered secure log file
read_file | sort | uniq -c | while read line;
do
  # convert line to array
  line_arr=($line)

  # number of attempts
  attempts=${line_arr[0]}
  # IP address
  ip_addr=${line_arr[1]}
  # connection type
  connection=${line_arr[2]}

  # check if the IP address is already blocked
  check=`$IP_TABLES -L | grep $ip_addr | wc -l`

  # if (attempts >= max attempts) AND ( check == 0 )
  if [ $attempts -ge $MAX_ATTEMPTS ] && [ $check -eq 0 ]; then
    # DROP IP address
    $IP_TABLES -A INPUT -s $ip_addr -j DROP;
    # record the dropped IP address in the drop log
    $IP_TABLES -L | grep $ip_addr >> droplog;
    # unblock the IP address after the time limit
    "$IP_TABLES -D INPUT -s $ip_addr -j DROP" | at now + "$TIME_LIMIT" minutes;
    # refresh the dropped IP address in the drop log
    $IP_TABLES -L | grep $ip_addr >> droplog;
  fi
done