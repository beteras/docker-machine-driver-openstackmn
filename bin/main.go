package main

import (
	"github.com/beteras/docker-machine-driver-openstackmn"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	// plugin.RegisterDriver(new(openstackmn.Driver))
	// What these args used for ?
	plugin.RegisterDriver(openstackmn.NewDriver("", ""))
}
