# docker-machine-openstackmn

This is a multi-network version of OpenStack docker-machine driver.

It's a copy of: https://github.com/robertjustjones/machine/tree/rackspace-net-switches

from this PR reverted: https://github.com/docker/machine/pull/2974

to build it

`GOGC=off CGOENABLED=0 go build -i -o ./bin docker-machine-driver-openstackmn ./bin`

now you can use a comma separated list of net-id's or net-name's for openstack

`--openstack-net-name dmz,nat,admin`

`--openstack-id-name xxx,yyy,zzz`

URL to use it in Rancher as node driver

`https://github.com/beteras/docker-machine-openstackmn/raw/master/bin/docker-machine-driver-openstackmn`
