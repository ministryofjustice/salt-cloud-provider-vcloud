salt-cloud-provider-vcloud
==========================

Salt Cloud Provider for VMWare vCloud Directors (5.1) for Salt Cloud ( >=
v2014.1.0, the integrated salt cloud rather than the standalone component)

Features
--------

- Creating VM on a single org VDC network
- Creating/Appending to NAT rules on vShield Edges

We will soon be adding support for creating and controlling firewall rules
relating to each box. We might also want to support multi-homed VMs soon.

Things this won't do
--------------------

- Supporting more than one VM inside a vApp
- Anything to do with catalog management (uploading or building new images)
- Creating Networks. (Because working out how to put this into a cloud.map
  cleanly is hard.)

Will this work for me?
======================

Hopefully! We'd love to say yes but we can't make any promises - each vCloud
Director API might well behave and new and interesting ways that we haven't
discovered (the one we use was bad enough).  If you do use this and find it
doesn't work right for you then open an issue and include an xml session dump
we can try to help (`libcloud.enable_debug(sys.stdout)`).

Contributing
============

How to Contribute

1. Clone this repository.
2. Add your feature/bug fix with unit tests
3. Submit a pull request on GitHub.

