package openstackmn

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"

	"github.com/rackspace/gophercloud"
)

type Driver struct {
	*drivers.BaseDriver

	AuthUrl          string
	ActiveTimeout    int
	Insecure         bool
	CaCert           string
	DomainID         string
	DomainName       string
	Username         string
	Password         string
	TenantName       string
	TenantId         string
	Region           string
	AvailabilityZone string
	EndpointType     string
	MachineId        string
	FlavorName       string
	FlavorId         string
	ImageName        string
	ImageId          string
	KeyPairName      string
	NetworkNames     []string
	NetworkIds       []string
	UserData         []byte
	PrivateKeyFile   string
	SecurityGroups   []string
	FloatingIpPool   string
	ComputeNetwork   bool
	FloatingIpPoolId string
	IpVersion        int
	ConfigDrive      bool
	metadata         string
	client           Client
	// ExistingKey keeps track of whether the key was created by us or we used an existing one. If an existing one was used, we shouldn't delete it when the machine is deleted.
	ExistingKey bool
}

const (
	defaultSSHUser       = "root"
	defaultSSHPort       = 22
	defaultActiveTimeout = 200
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "OS_AUTH_URL",
			Name:   "openstackmn-auth-url",
			Usage:  "OpenStack authentication URL",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_INSECURE",
			Name:   "openstackmn-insecure",
			Usage:  "Disable TLS credential checking.",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_CACERT",
			Name:   "openstackmn-cacert",
			Usage:  "CA certificate bundle to verify against",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_DOMAIN_ID",
			Name:   "openstackmn-domain-id",
			Usage:  "OpenStack domain ID (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_DOMAIN_NAME",
			Name:   "openstackmn-domain-name",
			Usage:  "OpenStack domain name (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USERNAME",
			Name:   "openstackmn-username",
			Usage:  "OpenStack username",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PASSWORD",
			Name:   "openstackmn-password",
			Usage:  "OpenStack password",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_TENANT_NAME",
			Name:   "openstackmn-tenant-name",
			Usage:  "OpenStack tenant name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_TENANT_ID",
			Name:   "openstackmn-tenant-id",
			Usage:  "OpenStack tenant id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_REGION_NAME",
			Name:   "openstackmn-region",
			Usage:  "OpenStack region name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_AVAILABILITY_ZONE",
			Name:   "openstackmn-availability-zone",
			Usage:  "OpenStack availability zone",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_ENDPOINT_TYPE",
			Name:   "openstackmn-endpoint-type",
			Usage:  "OpenStack endpoint type (adminURL, internalURL or publicURL)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLAVOR_ID",
			Name:   "openstackmn-flavor-id",
			Usage:  "OpenStack flavor id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLAVOR_NAME",
			Name:   "openstackmn-flavor-name",
			Usage:  "OpenStack flavor name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_IMAGE_ID",
			Name:   "openstackmn-image-id",
			Usage:  "OpenStack image id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_IMAGE_NAME",
			Name:   "openstackmn-image-name",
			Usage:  "OpenStack image name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_KEYPAIR_NAME",
			Name:   "openstackmn-keypair-name",
			Usage:  "OpenStack keypair to use to SSH to the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PRIVATE_KEY_FILE",
			Name:   "openstackmn-private-key-file",
			Usage:  "Private keyfile to use for SSH (absolute path)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_NETWORK_ID",
			Name:   "openstackmn-net-id",
			Usage:  "OpenStack comma separated networks id the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USER_DATA_FILE",
			Name:   "openstackmn-user-data-file",
			Usage:  "File containing an openstack userdata script",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_NETWORK_NAME",
			Name:   "openstackmn-net-name",
			Usage:  "OpenStack comma separated network names the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SECURITY_GROUPS",
			Name:   "openstackmn-sec-groups",
			Usage:  "OpenStack comma separated security groups for the machine",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_NOVA_NETWORK",
			Name:   "openstackmn-nova-network",
			Usage:  "Use the nova networking services instead of neutron.",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLOATINGIP_POOL",
			Name:   "openstackmn-floatingip-pool",
			Usage:  "OpenStack floating IP pool to get an IP from to assign to the instance (first network only)",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "OS_IP_VERSION",
			Name:   "openstackmn-ip-version",
			Usage:  "OpenStack version of IP address assigned for the machine",
			Value:  4,
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SSH_USER",
			Name:   "openstackmn-ssh-user",
			Usage:  "OpenStack SSH user",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_SSH_PORT",
			Name:   "openstackmn-ssh-port",
			Usage:  "OpenStack SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_ACTIVE_TIMEOUT",
			Name:   "openstackmn-active-timeout",
			Usage:  "OpenStack active timeout",
			Value:  defaultActiveTimeout,
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_CONFIG_DRIVE",
			Name:   "openstackmn-config-drive",
			Usage:  "Enables the OpenStack config drive for the instance",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_METADATA",
			Name:   "openstackmn-metadata",
			Usage:  "OpenStack Instance Metadata (e.g. key1,value1,key2,value2)",
			Value:  "",
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return NewDerivedDriver(hostName, storePath)
}

func NewDerivedDriver(hostName, storePath string) *Driver {
	return &Driver{
		client:        &GenericClient{},
		ActiveTimeout: defaultActiveTimeout,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) SetClient(client Client) {
	d.client = client
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "openstackmn"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AuthUrl = flags.String("openstackmn-auth-url")
	d.ActiveTimeout = flags.Int("openstackmn-active-timeout")
	d.Insecure = flags.Bool("openstackmn-insecure")
	d.CaCert = flags.String("openstackmn-cacert")
	d.DomainID = flags.String("openstackmn-domain-id")
	d.DomainName = flags.String("openstackmn-domain-name")
	d.Username = flags.String("openstackmn-username")
	d.Password = flags.String("openstackmn-password")
	d.TenantName = flags.String("openstackmn-tenant-name")
	d.TenantId = flags.String("openstackmn-tenant-id")
	d.Region = flags.String("openstackmn-region")
	d.AvailabilityZone = flags.String("openstackmn-availability-zone")
	d.EndpointType = flags.String("openstackmn-endpoint-type")
	d.FlavorId = flags.String("openstackmn-flavor-id")
	d.FlavorName = flags.String("openstackmn-flavor-name")
	d.ImageId = flags.String("openstackmn-image-id")
	d.ImageName = flags.String("openstackmn-image-name")
	if flags.String("openstackmn-net-id") != "" {
		d.NetworkIds = strings.Split(flags.String("openstackmn-net-id"), ",")
	}
	if flags.String("openstackmn-net-name") != "" {
		d.NetworkNames = strings.Split(flags.String("openstackmn-net-name"), ",")
	}
	d.metadata = flags.String("openstackmn-metadata")
	if flags.String("openstackmn-sec-groups") != "" {
		d.SecurityGroups = strings.Split(flags.String("openstackmn-sec-groups"), ",")
	}
	d.FloatingIpPool = flags.String("openstackmn-floatingip-pool")
	d.IpVersion = flags.Int("openstackmn-ip-version")
	d.ComputeNetwork = flags.Bool("openstackmn-nova-network")
	d.SSHUser = flags.String("openstackmn-ssh-user")
	d.SSHPort = flags.Int("openstackmn-ssh-port")
	d.ExistingKey = flags.String("openstackmn-keypair-name") != ""
	d.KeyPairName = flags.String("openstackmn-keypair-name")
	d.PrivateKeyFile = flags.String("openstackmn-private-key-file")
	d.ConfigDrive = flags.Bool("openstackmn-config-drive")

	if flags.String("openstackmn-user-data-file") != "" {
		userData, err := ioutil.ReadFile(flags.String("openstackmn-user-data-file"))
		if err == nil {
			d.UserData = userData
		} else {
			return err
		}
	}

	d.SetSwarmConfigFromFlags(flags)

	return d.checkConfig()
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}

	log.Debug("Looking for the IP address...", map[string]string{"MachineId": d.MachineId})

	if err := d.initCompute(); err != nil {
		return "", err
	}

	addressType := Fixed
	if d.FloatingIpPool != "" {
		addressType = Floating
	}

	// Looking for the IP address in a retry loop to deal with OpenStack latency
	for retryCount := 0; retryCount < 200; retryCount++ {
		addresses, err := d.client.GetInstanceIPAddresses(d)
		if err != nil {
			return "", err
		}
		for _, a := range addresses {
			if a.AddressType == addressType && a.Version == d.IpVersion {
				return a.Address, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("No IP found for the machine")
}

func (d *Driver) GetState() (state.State, error) {
	log.Debug("Get status for OpenStack instance...", map[string]string{"MachineId": d.MachineId})
	if err := d.initCompute(); err != nil {
		return state.None, err
	}

	s, err := d.client.GetInstanceState(d)
	if err != nil {
		return state.None, err
	}

	log.Debug("State for OpenStack instance", map[string]string{
		"MachineId": d.MachineId,
		"State":     s,
	})

	switch s {
	case "ACTIVE":
		return state.Running, nil
	case "PAUSED":
		return state.Paused, nil
	case "SUSPENDED":
		return state.Saved, nil
	case "SHUTOFF":
		return state.Stopped, nil
	case "BUILDING":
		return state.Starting, nil
	case "ERROR":
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) Create() error {
	if err := d.resolveIds(); err != nil {
		return err
	}
	if d.KeyPairName != "" {
		if err := d.loadSSHKey(); err != nil {
			return err
		}
	} else {
		d.KeyPairName = fmt.Sprintf("%s-%s", d.MachineName, mcnutils.GenerateRandomID())
		if err := d.createSSHKey(); err != nil {
			return err
		}
	}
	if err := d.createMachine(); err != nil {
		return err
	}
	if err := d.waitForInstanceActive(); err != nil {
		return err
	}
	if d.FloatingIpPool != "" {
		if err := d.assignFloatingIP(); err != nil {
			return err
		}
	}
	if err := d.lookForIPAddress(); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Start() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StartInstance(d)
}

func (d *Driver) Stop() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StopInstance(d)
}

func (d *Driver) Restart() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.RestartInstance(d)
}

func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) Remove() error {
	log.Debug("deleting instance...", map[string]string{"MachineId": d.MachineId})
	log.Info("Deleting OpenStack instance...")
	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.DeleteInstance(d); err != nil {
		if gopherErr, ok := err.(*gophercloud.UnexpectedResponseCodeError); ok {
			if gopherErr.Actual == http.StatusNotFound {
				log.Warn("Remote instance does not exist, proceeding with removing local reference")
			} else {
				return err
			}
		} else {
			return err
		}
	}
	if !d.ExistingKey {
		log.Debug("deleting key pair...", map[string]string{"Name": d.KeyPairName})
		if err := d.client.DeleteKeyPair(d, d.KeyPairName); err != nil {
			if gopherErr, ok := err.(*gophercloud.UnexpectedResponseCodeError); ok {
				if gopherErr.Actual == http.StatusNotFound {
					log.Warn("Keypair already deleted")
				} else {
					return err
				}
			} else {
				return err
			}
		}
	}
	return nil
}

func (d *Driver) GetMetadata() map[string]string {
	metadata := make(map[string]string)

	if d.metadata != "" {
		items := strings.Split(d.metadata, ",")
		if len(items) > 0 && len(items)%2 != 0 {
			log.Warnf("Metadata are not key value in pairs. %d elements found", len(items))
		}
		for i := 0; i < len(items)-1; i += 2 {
			metadata[items[i]] = items[i+1]
		}
	}

	return metadata
}

const (
	errorMandatoryEnvOrOption    string = "%s must be specified either using the environment variable %s or the CLI option %s"
	errorMandatoryOption         string = "%s must be specified using the CLI option %s"
	errorExclusiveOptions        string = "Either %s or %s must be specified, not both"
	errorBothOptions             string = "Both %s and %s must be specified"
	errorMandatoryTenantNameOrID string = "Tenant id or name must be provided either using one of the environment variables OS_TENANT_ID and OS_TENANT_NAME or one of the CLI options --openstackmn-tenant-id and --openstackmn-tenant-name"
	errorWrongEndpointType       string = "Endpoint type must be 'publicURL', 'adminURL' or 'internalURL'"
	errorUnknownFlavorName       string = "Unable to find flavor named %s"
	errorUnknownImageName        string = "Unable to find image named %s"
	errorUnknownNetworkName      string = "Unable to find network named %s"
	errorUnknownTenantName       string = "Unable to find tenant named %s"
)

func (d *Driver) checkConfig() error {
	if d.AuthUrl == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Authentication URL", "OS_AUTH_URL", "--openstackmn-auth-url")
	}
	if d.Username == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Username", "OS_USERNAME", "--openstackmn-username")
	}
	if d.Password == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Password", "OS_PASSWORD", "--openstackmn-password")
	}
	if d.TenantName == "" && d.TenantId == "" {
		return fmt.Errorf(errorMandatoryTenantNameOrID)
	}

	if d.FlavorName == "" && d.FlavorId == "" {
		return fmt.Errorf(errorMandatoryOption, "Flavor name or Flavor id", "--openstackmn-flavor-name or --openstackmn-flavor-id")
	}
	if d.FlavorName != "" && d.FlavorId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Flavor name", "Flavor id")
	}

	if d.ImageName == "" && d.ImageId == "" {
		return fmt.Errorf(errorMandatoryOption, "Image name or Image id", "--openstackmn-image-name or --openstackmn-image-id")
	}
	if d.ImageName != "" && d.ImageId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Image name", "Image id")
	}

	if len(d.NetworkNames) > 0 && len(d.NetworkIds) > 0 {
		return fmt.Errorf(errorExclusiveOptions, "Network names", "Network ids")
	}
	if d.EndpointType != "" && (d.EndpointType != "publicURL" && d.EndpointType != "adminURL" && d.EndpointType != "internalURL") {
		return fmt.Errorf(errorWrongEndpointType)
	}
	if (d.KeyPairName != "" && d.PrivateKeyFile == "") || (d.KeyPairName == "" && d.PrivateKeyFile != "") {
		return fmt.Errorf(errorBothOptions, "KeyPairName", "PrivateKeyFile")
	}
	return nil
}

func (d *Driver) resolveIds() error {
	if len(d.NetworkNames) > 0 && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}
		networkIds, err := d.client.GetNetworkIDs(d)
		if err != nil {
			return err
		}

		if len(networkIds) == 0 {
			return fmt.Errorf(errorUnknownNetworkName, strings.Join(d.NetworkNames, ",")) // TODO specific name
		}

		d.NetworkIds = networkIds
		for i, networkName := range d.NetworkNames {
			log.Debug("Found network id using its name", map[string]string{
				"Name": networkName,
				"ID":   d.NetworkIds[i],
			})
		}
	}

	if d.FlavorName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		flavorID, err := d.client.GetFlavorID(d)

		if err != nil {
			return err
		}

		if flavorID == "" {
			return fmt.Errorf(errorUnknownFlavorName, d.FlavorName)
		}

		d.FlavorId = flavorID
		log.Debug("Found flavor id using its name", map[string]string{
			"Name": d.FlavorName,
			"ID":   d.FlavorId,
		})
	}

	if d.ImageName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		imageID, err := d.client.GetImageID(d)

		if err != nil {
			return err
		}

		if imageID == "" {
			return fmt.Errorf(errorUnknownImageName, d.ImageName)
		}

		d.ImageId = imageID
		log.Debug("Found image id using its name", map[string]string{
			"Name": d.ImageName,
			"ID":   d.ImageId,
		})
	}

	if d.FloatingIpPool != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}
		f, err := d.client.GetFloatingIPPoolID(d)

		if err != nil {
			return err
		}

		if f == "" {
			return fmt.Errorf(errorUnknownNetworkName, d.FloatingIpPool)
		}

		d.FloatingIpPoolId = f
		log.Debug("Found floating IP pool id using its name", map[string]string{
			"Name": d.FloatingIpPool,
			"ID":   d.FloatingIpPoolId,
		})
	}

	if d.TenantName != "" && d.TenantId == "" {
		if err := d.initIdentity(); err != nil {
			return err
		}
		tenantId, err := d.client.GetTenantID(d)

		if err != nil {
			return err
		}

		if tenantId == "" {
			return fmt.Errorf(errorUnknownTenantName, d.TenantName)
		}

		d.TenantId = tenantId
		log.Debug("Found tenant id using its name", map[string]string{
			"Name": d.TenantName,
			"ID":   d.TenantId,
		})
	}

	return nil
}

func (d *Driver) initCompute() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitComputeClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initIdentity() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitIdentityClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initNetwork() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitNetworkClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) loadSSHKey() error {
	log.Debug("Loading Key Pair", d.KeyPairName)
	if err := d.initCompute(); err != nil {
		return err
	}
	log.Debug("Loading Private Key from", d.PrivateKeyFile)
	privateKey, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err
	}
	publicKey, err := d.client.GetPublicKey(d.KeyPairName)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.privateSSHKeyPath(), privateKey, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.publicSSHKeyPath(), publicKey, 0600); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createSSHKey() error {
	sanitizeKeyPairName(&d.KeyPairName)
	log.Debug("Creating Key Pair...", map[string]string{"Name": d.KeyPairName})
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}
	publicKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.CreateKeyPair(d, d.KeyPairName, string(publicKey)); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createMachine() error {
	log.Debug("Creating OpenStack instance...", map[string]string{
		"FlavorId": d.FlavorId,
		"ImageId":  d.ImageId,
	})

	if err := d.initCompute(); err != nil {
		return err
	}
	instanceID, err := d.client.CreateInstance(d)
	if err != nil {
		return err
	}
	d.MachineId = instanceID
	return nil
}

func (d *Driver) assignFloatingIP() error {
	var err error

	if d.ComputeNetwork {
		err = d.initCompute()
	} else {
		err = d.initNetwork()
	}

	if err != nil {
		return err
	}

	ips, err := d.client.GetFloatingIPs(d)
	if err != nil {
		return err
	}

	var floatingIP *FloatingIP

	log.Debugf("Looking for an available floating IP", map[string]string{
		"MachineId": d.MachineId,
		"Pool":      d.FloatingIpPool,
	})

	for _, ip := range ips {
		if ip.PortId == "" {
			log.Debug("Available floating IP found", map[string]string{
				"MachineId": d.MachineId,
				"IP":        ip.Ip,
			})
			floatingIP = &ip
			break
		}
	}

	if floatingIP == nil {
		floatingIP = &FloatingIP{}
		log.Debug("No available floating IP found. Allocating a new one...", map[string]string{"MachineId": d.MachineId})
	} else {
		log.Debug("Assigning floating IP to the instance", map[string]string{"MachineId": d.MachineId})
	}

	if err := d.client.AssignFloatingIP(d, floatingIP); err != nil {
		return err
	}
	d.IPAddress = floatingIP.Ip
	return nil
}

func (d *Driver) waitForInstanceActive() error {
	log.Debug("Waiting for the OpenStack instance to be ACTIVE...", map[string]string{"MachineId": d.MachineId})
	if err := d.client.WaitForInstanceStatus(d, "ACTIVE"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) lookForIPAddress() error {
	ip, err := d.GetIP()
	if err != nil {
		return err
	}
	d.IPAddress = ip
	log.Debug("IP address found", map[string]string{
		"IP":        ip,
		"MachineId": d.MachineId,
	})
	return nil
}

func (d *Driver) privateSSHKeyPath() string {
	return d.GetSSHKeyPath()
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

func sanitizeKeyPairName(s *string) {
	*s = strings.Replace(*s, ".", "_", -1)
}
