# docker-machine-openstackmn

This is a multi-network version of OpenStack docker-machine driver.

It's a mix between all these files:
- https://github.com/docker/machine/tree/1e3fa2d2cf0cd4b9b54728a9146897a3990a18f0/drivers/openstack
- https://github.com/robertjustjones/machine/tree/07cadc68a53c818bf83806e854bbe6ac1ddeda66/drivers/openstack

from this PR reverted: https://github.com/docker/machine/pull/2974

to build it

`make`

now you can use a comma separated list of net-id's or net-name's for openstack

`--openstack-net-name dmz,nat,admin`

`--openstack-id-name xxx,yyy,zzz`

URL to use it in Rancher as node driver

`https://github.com/beteras/docker-machine-openstackmn/raw/master/bin/docker-machine-driver-openstackmn`
