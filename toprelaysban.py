#!/usr/bin/python
#
# This script automatically pulls a certain number of Top Spam Relays as
# detected by Sophos Puremessage, and adds their network block to
# the IP Blocker Inclusions list.

# Psycopg2 for Postgres Interface
import psycopg2
import subprocess

def get_pmx_top_spam_relays (limit, threshold, interval):

    # Retrieves the top <limit> Spam Relays
    # Above <threshold> messages
    # Over the last <interval>
    # Returns the relays as a list
    # Example: relays = get_pmx_top_spam_relays (10, 500, "1 day")

    # Replace this with your database parameters. Should be the same if
    # you are running the script locally

    DB_STRING="dbname=pmx_quarantine user=pmx6 host=localhost"

    conn = psycopg2.connect(DB_STRING)
    cur = conn.cursor()

    query = ("SELECT relay FROM prd_relays_by_type WHERE type = 'spam' AND \
              period_start >= (now() - \'" + str(interval) + "\'::INTERVAL) ORDER BY tally DESC limit " + str(limit))
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except:
        print "Unable to execute query."

    return rows

def read_ipblocklist (filename):

    # retreives the IP blocking inclusion list and reads it into a list
    # returns: that list

    with open(filename) as f:
        lines = f.read().splitlines()

    return lines

def write_ipblocklist(new_blocklist, filename):

    # writes a python list of IPs to block to the ip blocking inclusions file

    ipblocklist = open(filename,'w')
    for item in new_blocklist:
        ipblocklist.write("%s\n" % item)

    return

def main():

    # get the top spam relays that have sent more than 500 spam messages

    toprelays = get_pmx_top_spam_relays(10, 500, "12 hours")

    # Splits the IP addresses at the last octect and converts to a subnet /24
    # This is totally arbitrary. I like to block the entire subnet block
    # when a spam relay is above a certain threshold. Could possibly be
    # totally irresponsible.

    toprelays = [row[0].rsplit('.', 1)[0] + ".0/24" for row in toprelays]

    # neat trick to remove duplicates in the list. convert it to a set and back

    IP_BLOCKLIST="/opt/pmx/etc/ip-blocking-inclusions"

    blockedips = read_ipblocklist(IP_BLOCKLIST)
    mergedlist = sorted(list (set(toprelays + blockedips)))

    write_ipblocklist(mergedlist, IP_BLOCKLIST)

    # sync the publication up with the other nodes
    subprocess.call(['/opt/pmx6/bin/pmx-share', '--publication', 'Policy_Inbound', 'sync'], shell=False)

if __name__ == '__main__':
  main()
