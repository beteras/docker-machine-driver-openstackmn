package main

import (
	"github.com/beteras/docker-machine-openstackmn"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(new(openstack.Driver))
}
