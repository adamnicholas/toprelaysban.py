#!/usr/bin/python
#
# This script automatically pulls a certain number of Top Spam Relays as
# detected by Sophos Puremessage, and adds their network block to
# the IP Blocker Inclusions list.

# Psycopg2 for Postgres Interface
import psycopg2
import subprocess

def get_pmx_top_spam_relays (threshold):

    # retrieves the top Spam Relays above <threshold> messages
    #select relay, tally from prd_relays_by_type where tally >= 500 and type = 'spam'
    # and period_start >= (now() - '1 day'::INTERVAL) order by tally desc;

    conn = psycopg2.connect("dbname=pmx_quarantine user=pmx6 host=localhost")
    cur = conn.cursor()
    query = ("SELECT relay FROM prd_relays_by_type WHERE type = 'spam' AND \
              period_start >= (now() - '1 day'::INTERVAL) ORDER BY tally DESC limit 10")
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except:
        print "Unable to execute query."

    return rows

def read_ipblocklist ():

    # retreives the IP blocking inclusion list and reads it into a list
    # returns: that list

    with open('/opt/pmx/etc/ip-blocking-inclusions') as f:
        lines = f.read().splitlines()

    return lines

def write_ipblocklist(blocklist):

    # writes a python list of IPs to block to the ip blocking inclusions file

    ipblocklist = open('/opt/pmx/etc/ip-blocking-inclusions','w')
    for item in blocklist:
        ipblocklist.write("%s\n" % item)

    return

def main():

    # get the top spam relays that have sent more than 500 spam messages

    toprelays = get_pmx_top_spam_relays(500)

    # Splits the IP addresses at the last octect and converts to a subnet /24
    # This is totally arbitrary. I like to block the entire subnet block
    # when a spam relay is above a certain threshold. Could possibly be
    # totally irresponsible.

    toprelays = [row[0].rsplit('.', 1)[0] + ".0/24" for row in toprelays]

    # neat trick to remove duplicates in the list. convert it to a set and back

    blockedips = read_ipblocklist()
    mergedlist = sorted(list (set(toprelays + blockedips)))

    write_ipblocklist(mergedlist)

    # sync the publication up with the other nodes
    subprocess.call(['/opt/pmx6/bin/pmx-share', '--publication', 'Policy_Inbound', 'sync'], shell=False)

if __name__ == '__main__':
  main()
