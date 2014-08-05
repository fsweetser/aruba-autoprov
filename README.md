aruba-autoprov
==============

This script is designed to automate the more tedious parts of
provisioning campus access points on an Aruba controller.  The
intended workflow goes like this:

  * Create a CSV file containing a list of MAC addresses, AP
    names, and AP groups.

  * Allow APs to bootstrap and associate with the controller in
    the default state.

  * Run the provision.pl script against the file and controller.

  * The script will first modify the cpsec whitelist to the
    desired state to allow the APs to authenticate.

  * The script will then pause and begin polling the controller
    to make sure the commands go through.

  * As the APs rebootstrap and come online, they will be
    provisioned according to the CSV file.

  * The script will again poll to ensure all APs complete
    provisioning.

At this point all APs should be online and operational.
