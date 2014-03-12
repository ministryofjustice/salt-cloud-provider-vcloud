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

Configuration
============

Explaining all of salt-cloud is a bigger task than we want and other people
have done it already.  For general info on configurating salt-cloud look at the
[the upstream docs](http://docs.saltstack.com/topics/cloud/index.html).

# salt-cloud config files

### cloud.providers

You will need to create a section in the cloud.provider file (by default this
file is /etc/salt/cloud.provider):

```
my_vcloud:
    provider: vcloud
    user: 221.63.6b164a
    org: 46-44-3-96a205
    secret: super-sekrit
    host: api.vcd.example.com

    private_key: /root/minion-ssh.pem
    ssh_username: provisioning
    display_ssh_output: True

```

### cloud.profiles

```
vcd_tiny_vdc_a:
  provider: my_vcloud
  image: ubuntu-precies-ad04aef
  size: tiny
  vdc: 'my-org-a (BASIC)'
```

The `provider` key is just a string - it just needs to match the key from the
`cloud.providers` file.

### cloud.map

```
vcdtiny_vdc_a:
  - loadbalancer.myapp:
      network: Admin
      # These are normal cloud.map settings and nothing to do with this
      # provider.
      minion:
        log_level: debug
      grains:
        roles:
          - loadbalancer
```

## Configuration reference

The provider understands the following configuration options below. Any of the
options can be specified in the providers, profiles or the map files. (Anything
in the map will override the profile which overrides the provider.)

- **user**: Required

  vCloud API user id without the '@<org-id>' part.

- **org**: Required

  vCloud organization ID.

- **secret**: Required

  Password for user@org in the vCloud API.

- **host** : Required

  The hostname where the vCloud Director API lives.

- **image**: Required

  Recommended location: cloud.profiles

  Which vApp template to build images from.

  The name of the vAppTemplate in an accessible catalog for this vCloud
  organization

- **vdc**: Required

  The name of the VDC to create the vApp in. This is the exact string displayed
  in the vCloud Director GUI, not the underlying ID.

- **network**: Required

  The name (not uuid) of the network in `vdc` to put this box on. This network
  must have IP pool configured.

- **size**: Optional

  Size of the VM (RAM & CPU) to configure the box to use. This is a lookup
  table, not the exact ram/cpu specifications.

- **ssh_username**: Optional

  Default: root

  Username to use on the minion when bootstrapping the (installing salt-minion)

- **dnat**: Optional

  Type: List of integers

  Ports to configure in the vShieldEdge to DNAT port forward to the internal IP
  for this machine. This will automatically set up rules on the first public IP
  available on the VSE.



Contributing
============

How to Contribute

1. Clone this repository.
2. Add your feature/bug fix with unit tests
3. Submit a pull request on GitHub.

