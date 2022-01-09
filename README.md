![license](https://img.shields.io/github/license/leinadred/phpipamCLIent)
![language](https://img.shields.io/github/languages/top/leinadred/phpipamCLIent)

# phpipamCLIent

CLI like phpipam client for showing networks, vlans and sections.

## Setup

URL of phpipam (ie 'http://phpipam.asd.fg') and AppID defined in API Settings will have to be set in the script.  
Authentication can then either be as a dialogue (user will be asked) or can be set up in the script too. The dialogue supports User&Pass and "AppCode" for authentication. To use an Appcode, leave the username blank.

### Python Modules

following Python modules are used

- urllib3
- argparse
- logging
- requests
- ipaddress
- json
- getpass

### Custom Fields

Custom fields can be added to output too (will add an example in extra file)

## Example

python3 phpipamclient.py show network 10.0.0.0/24  
python3 phpipamclient.py show section lab  
python3 phpipamclient.py show vlan 10

If found, output:

```text
Network found, details below:

----------------------------------------------------------------

    Section:            
    Customer:           
    Subnet/Mask:        192.168.10.0/24
    Description:        servers
    Nameservers:        ns_servers {192.168.10.12}
    Master Subnet:      master
    VLan (VLan Name):   10 (192.168.10/servers)
    L2 Domain:          L2Domain
--------------------------------
    Link:               http://phpipam.asd.fg/subnets/5/7
----------------------------------------------------------------`

```

-------------------------------------------------------------------------------

```text

Section(s) found, details below:
----------------------------------------------------------------
Section Name:       LAB
Description:        None
Master Section:     My_Own_Sections
Section DNS:        None
Last Change:        None
Subnets:            1
                    192.168.10.0/24    servers
                        
--------------------------------    
Link:               http://phpipam.asd.fg/subnets/5
----------------------------------------------------------------

```

-------------------------------------------------------------------------------

```text

VLAN(s) found, details below:
----------------------------------------------------------------
    Section:            LAB
    Customer:           None
    Vlan ID:            3
    L2 Domain:          L2Domain
    Name:               192.168.10/servers
    Description:        None
    linked subnet:      
                Subnet:         192.168.10.0/24
                Description:    servers
                Link:           http://phpipam.asd.fg/subnets/5/7
--------------------------------    
    Link:               http://phpipam.asd.fg/vlan/3
----------------------------------------------------------------

```

## Coming up

- vlan / network creation
- example file for custom fields
