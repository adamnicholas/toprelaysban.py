# toprelaysban.py

This is quite possibly the most specific piece of Python code ever written, but I very badly needed to automate something that I have been doing by hand. This script retrieves the Top Spam Relays by IP as determined by PureMessage over a certain threshold of spam sent (500) in a certain time period (24 hours). Then it converts these relay IPs to class C subnets (/24), adds them to the PureMessage IP Blocklist Inclusion list, and syncronizes the policy from the master node to the endpoints.

## The Environment

Sophos PureMessage for Unix version 6.3.0

Three nodes, one master DB with the PureMessage management software and a PostgreSQL database, two inbound nodes with Postfix and PureMessage running on a local port set up as a content_filter. 

The master database has all of the policy configuration that gets pushed to the inbound SMTP servers. The configuration we're most concerned about in this script is a subscription named "Policy_Inbound". Tied to that subscription are a bunch of lists for configurations like global blacklists, whitelists, IP blocker inclusions and exclusions, and of course the policy.siv. 

This script is in particular concerned with the ip-blocking-inclusions file that is published to the Policy_Inbound subscription. This subscription is probably called something else in your configuration, but the concept should work the same. 
