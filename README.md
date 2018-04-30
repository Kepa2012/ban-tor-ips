# Ban TOR IPs
This project provides a BASH script that bans TOR nodes from accessing a server.

The list of TOR nodes is retrieved from [here](https://www.dan.me.uk/tornodes) everytime the script is run. In case there is any trouble downloading the list of node, an email is sent to desired recipient.

# Requirements
* [SendEmail](http://caspian.dotconf.net/menu/Software/SendEmail/) a lightweight, command line SMTP email client has to be installed.
* The user running the script must have granted access to iptables.

# Acknowledgments
Thanks to [Daniel Austin MBCS](https://www.dan.me.uk/about) for compiling the list of TOR nodes.
