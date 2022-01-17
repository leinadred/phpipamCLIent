# Daniel Meier
# import modules
import urllib3
import argparse
import logging
import requests
import ipaddress
import getpass
urllib3.disable_warnings()

#######################################################################################################

#######################################################################################################
baseurl = ''                                        # put in PHPIPAM URL (http(s)://hostname-or-fqdn/)
appid = ''                                          # AppID (configured at API mnu)
apiusername = ''                                    # if auth is set to "User token"
apiuserpass = ''                                    # if auth is set to "User token"    
apitoken = ''                                       # if auth is set to "App roken"
#######################################################################################################

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='extended logging')
parser.add_argument('-a', '--appid', help='set AppID ( overrides the app id set in scriptfile)')
parser.add_argument('-k', '--key', help='API Key (overrides Settings in script file)')
parser.add_argument('-u', '--baseurl', help='PHPIPAM Base URL (ie http://phpipam.asd.fg - overrides Settings in script file)')

subparser = parser.add_subparsers(required=True, dest='cmd', help='Tell what to do (show||search||set||create)')

# show known network 
parser_show = subparser.add_parser('show')
parser_show.add_argument('object', nargs='*', type=str, default=None, help='object to show / edit /create - "show network 10.0.0.0/8 192.168.100.0/24" (currently supported: network | vlan | section | ip | nameservers)')

#parser_show.set_defaults(func=funshow)

# search command (when IP is not known, search for hostname)
parser_search = subparser.add_parser('search')
parser_search.add_argument('object', nargs='*', type=str, default=None, help='search for address object by hostname')

#parser_search.set_defaults(func=funsearch)

# set command for altering object attributes
parser_set = subparser.add_parser('set')
parser_set.add_argument('object', nargs='*', type=str, default=None, help='set objects attribute to new value (single networks / ip / vlan only)\nExample: set network (subnet id) nameserver (nameservers id)')

# create command (currently not implemented yet)
parser_create = subparser.add_parser('create')
parser_create.add_argument('object', nargs='*', type=str, default=None, help='create new object - for example "subnet(CIDR)" or "vlanID"')

# parse the args and call whatever function was selected
args = parser.parse_args()
if args.verbose:logging.basicConfig( level=logging.DEBUG)
logging.debug(args.object)


if args.verbose:logging.basicConfig( level=logging.DEBUG)

# overriding preset values with arguments
if args.appid != None: appid = args.appid
if args.key: apitoken = args.key
if args.baseurl: baseurl = args.baseurl
logging.debug('Setup: \nBase URL: '+baseurl+'\nApp ID: '+appid+'\nAPITOKEN '+apitoken)
if baseurl[-1] == '/': baseurl = baseurl[:-1]
apiurl = baseurl+'/api/'+appid               # creating URL to API Application
#######################################################################################################

#LogIn - obtaining session token, if Authis set to "User Token", else App token is sent with every request.
if len(apiusername)==0 and len(apiuserpass)==0:
    if len(apitoken)==0:
        print('No authentication provided, please enter credentials! (enter apptoken as password with empty username)')
        apiusername=input("API User name: ")
        apiuserpass=getpass.getpass("Password: ")
        if apiusername != '' and apiuserpass != '':
            logging.debug('trying user '+apiusername+' with pass *****')
            print(requests.post(apiurl+'/user', auth=(apiusername, apiuserpass), verify=False).json()['code'])
            if requests.post(apiurl+'/user', auth=(apiusername, apiuserpass), verify=False).json()['code'] != 200:
                raise Exception('Unauthorized - check auth settings at phpipam or values entered')
            else:
                token=requests.post(apiurl+'/user', auth=(apiusername, apiuserpass), verify=False).json()['data']['token']
        elif len(apiusername)==0 and len(apiuserpass)>0:
            authresult = requests.post(apiurl+'/sections/0', headers={'token':apiuserpass}, verify=False).json()['code']
            if authresult == '200':
                token = apiuserpass
            else:
                raise Exception('Got "'+str(authresult)+'" - Response Code - check auth settings at phpipam or values entered')
        else: print('something went wrong, please try again or check script / auth settings')
    else:
        # Testing apitoken by GETting Section '0' Infos
        authresult = requests.get(apiurl+'/sections/0', headers={'token':apitoken}, verify=False).json()
        if authresult['code'] == 200:
            token = apitoken
        else: 
            raise Exception('Got "'+str(authresult)+'" - Response Code - check auth settings at phpipam or values entered. Token correct?')
else:
    token = requests.post(apiurl+'/user', auth=(apiusername, apiuserpass), verify=False).json()['data']['token']
logging.debug('auth Done - token: '+token)
apiusername=''; apiuserpass=''; apitoken=''

#######################################################################################################

logging.debug(args.object)

#######################################################################################################
# Functions
def funshow(args,token):
    if args.object[0]=='network':
        if args.object[1]=='custom':
            logging.debug('showing custom fields\n\n')
            resp = requests.get(apiurl+'/subnets/custom_fields/', headers={'token':str(token)}, verify=False).json()
            print('----------------------------------------------------------------')
            for a in resp['data']:
                print('''Custom Fields for networks "{0}":
Name:                   {0}
Comment:                {1}
Type:                   {2}
Null allowed:           {3}
Default value:          {4}
----------------------------------------------------------------'''.format(str(resp['data'][a]['name']), str(resp['data'][a]['Comment']),str(resp['data'][a]['type']), str(resp['data'][a]['Null']), str(resp['data'][a]['Default'])))
        else:
            for subnet in args.object:
                if not subnet == 'network':
                    resp = requests.get(apiurl+'/subnets/search/'+subnet, headers={'token':str(token)}, verify=False).json()
                    logging.debug(str(resp)+'\n\n\n')
                    if resp['success']:
                        for result in resp['data']:
                            if result['vlanId'] != None:
                                vlanresp = requests.get(apiurl+'/vlan/'+str(result['vlanId']), headers={'token':str(token)}, verify=False).json()
                                vlanid = vlanresp['data']['number']
                                vlanname = vlanresp['data']['name']
                                if vlanresp['data']['domainId'] != 'null':
                                    vlandom = requests.get(apiurl+'/l2domains/'+vlanresp['data']['domainId'], headers={'token':str(token)}, verify=False).json()['data']['name']
                            else: vlanid = 'none defined'
                            if result['nameserverId'] != '0':
                                nameserversn = requests.get(apiurl+'/tools/nameservers/'+str(result['nameserverId']), headers={'token':str(token)}, verify=False).json()['data']['name']
                                nameserverss = requests.get(apiurl+'/tools/nameservers/'+str(result['nameserverId']), headers={'token':str(token)}, verify=False).json()['data']['namesrv1']
                            else: nameserversn = 'none defined'
                            section = requests.get(apiurl+'/sections/'+str(result['sectionId'])+'/', headers={'token':str(token)}, verify=False).json()['data']['name']
                            if result['masterSubnetId'] != '0':
                                subnetmaster = requests.get(apiurl+'/subnets/'+result['masterSubnetId'], headers={'token':str(token)}, verify=False).json()['data']['name']
                            else:
                                subnetmaster = 'Root'
                            subnet = str(ipaddress.IPv4Network(str(result['subnet'])+'/'+str(result['mask'])).with_netmask)
                            subnetdesc = str(result['description'])
                            subnetedit = str(result['editDate'])
                            subnetscandisc = str(result['lastScan'])+' // '+str(result['lastDiscovery'])
                            print('''\
Network found, details below:
----------------------------------------------------------------
    Section:            {0}
    Subnet/Mask:        {1}
    Description:        {2}
    Nameservers:        {3}
    Master Subnet:      {4}
    VLan (VLan Name):   {5} ({6})
    L2 Domain:          {7}
    Last Edit:          {8}
    Scan/Discovery:     {9}
--------------------------------    
    Link:               {10}
----------------------------------------------------------------


'''.format(section,subnet,subnetdesc,nameserversn+' {'+nameserverss+'}',subnetmaster,str(vlanid), str(vlanname),str(vlandom),subnetedit,subnetscandisc,str(baseurl+str('/subnets/'+result['sectionId']+'/'+result['id']).replace('//','/'))))
                            section='';subnet='';vlanid = '';subnetdesc='';nameserverss = ''; nameserversn = '';vlanname = ''; vlandom = ''; subnetedit = '';subnetscandisc = ''
                    else: print('Network "{}" not found or not authorized!'.format(subnet))
                vlanid = ''; vlanname = ''; vlandom = ''; nameserverss = ''; nameserversn = ''; section = ''
            
    elif args.object[0]=='vlan':
        for vlan in args.object:
            if not vlan == 'vlan':
                resp = requests.get(apiurl+'/vlan/search/'+vlan, headers={'token':str(token)}, verify=False).json()
                logging.debug(str(resp)+'\n\n\n')
                if resp['success']:
                    for data in resp['data']:
                        logging.debug('Data:'+str(data))
                        vlanid = data['vlanId']
                        vlanidnumber = data['number']
                        vlandata = requests.get(apiurl+'/vlan/'+vlanid, headers={'token':str(token)}, verify=False).json()
                        vlancustomer = vlandata['data']['customer_id']
                        vlandomain = requests.get(apiurl+'/l2domains/'+vlandata['data']['domainId'], headers={'token':str(token)}, verify=False).json()
                        vlansection = requests.get(apiurl+'/sections/'+vlandomain['data']['sections'], headers={'token':str(token)}, verify=False).json()['data']['name']
                        vlandomain = vlandomain['data']['name']
                        vlanname = data['name']
                        vlandesc = data['description']
                        vlansubnet = ''
                        for vlansub in requests.get(apiurl+'/vlan/'+vlanid+'/subnets/', headers={'token':str(token)}, verify=False).json()['data']:
                            vlansubnet = vlansubnet+'\n\t\tSubnet:\t\t{0}\n\t\tDescription:\t{1}\n\t\tLink:\t\t{2}'.format(vlansub['subnet']+'/'+vlansub['mask'],vlansub['description'],str(baseurl+'subnets/'+vlansub['sectionId']+'/'+vlansub['id']))
                        vlanlink = str(baseurl+'vlan/'+vlanid).replace('//','/')
                        print('''\
VLAN(s) found, details below:
----------------------------------------------------------------
    Section:            {0}
    Customer:           {1}
    Vlan ID:            {2}
    L2 Domain:          {3}
    Name:               {4}
    Description:        {5}
    linked subnet:      {6}
--------------------------------    
    Link:               {7}
----------------------------------------------------------------


'''.format(vlansection,vlancustomer,vlanidnumber,vlandomain,vlanname,vlandesc,vlansubnet,vlanlink))


    elif args.object[0]=='section':
        for section in args.object:
            if not section == 'section':
                if section == 'all':
                    resp = requests.get(apiurl+'/sections/', headers={'token':str(token)}, verify=False).json()
                    logging.debug(str(resp)+'\n\n\n')
                    if resp['success']:
                        for data in resp['data']:
                            logging.debug('Data:'+str(data))
                            sectionid = data['id']
                            sectionname = data['name']
                            sectiondescription = data['description']
                            if data['masterSection'] != '0':
                                mastersection = requests.get(apiurl+'/sections/'+str(data['masterSection'])+'/', headers={'token':str(token)}, verify=False).json()['data']['name']
                            else: 
                                mastersection = 'root'
                            if requests.get(apiurl+'/sections/'+data['id']+'/subnets', headers={'token':str(token)}, verify=False).json()['code'] == 200:
                                subnetinfo = str(len(requests.get(apiurl+'/sections/'+data['id']+'/subnets', headers={'token':str(token)}, verify=False).json()['data']))+'\n                        '
                                for subnet in requests.get(apiurl+'/sections/'+data['id']+'/subnets', headers={'token':str(token)}, verify=False).json()['data']:
                                    subnetinfo = subnetinfo+'''{0}/{1} \t{2}
                    '''.format(subnet['subnet'],subnet['mask'], subnet['description'])
                            else:
                                subnetinfo = None
                            sectiondns =  data['DNS']
                            lastchange = data['editDate']
                            sectionlink = str(baseurl+str('subnets/'+sectionid).replace('//','/'))
                            print('''\
Section(s) found, details below:
----------------------------------------------------------------
    Section Name:       {0}
    Description:        {1}
    Master Section:     {2}
    Section DNS:        {3}
    Last Change:        {4}
    Subnets:            {5}
--------------------------------    
    Link:               {6}
----------------------------------------------------------------


'''.format(sectionname,sectiondescription,mastersection,sectiondns,lastchange,subnetinfo,sectionlink))
                else:
                    resp = requests.get(apiurl+'/sections/'+section+'/', headers={'token':str(token)}, verify=False).json()
                    if resp['success']:
                        data = resp['data']
                        logging.debug('Data:'+str(data))
                        sectionid = data['id']
                        sectionname = data['name']
                        sectiondescription = data['description']
                        if data['masterSection'] != '0':
                            mastersection = requests.get(apiurl+'/sections/'+str(data['masterSection'])+'/', headers={'token':str(token)}, verify=False).json()['data']['name']
                        else: 
                            mastersection = 'root'
                        if requests.get(apiurl+'/sections/'+data['id']+'/subnets', headers={'token':str(token)}, verify=False).json()['code'] == 200:
                            subnetinfo = str(len(requests.get(apiurl+'/sections/'+data['id']+'/subnets', headers={'token':str(token)}, verify=False).json()['data']))+'\n                    '
                            for subnet in requests.get(apiurl+'/sections/'+data['id']+'/subnets', headers={'token':str(token)}, verify=False).json()['data']:
                                subnetinfo = subnetinfo+'''{0}/{1} \t{2}
                    '''.format(subnet['subnet'],subnet['mask'], subnet['description'])
                        else:
                            subnetinfo = None
                        sectiondns =  data['DNS']
                        lastchange = data['editDate']
                        sectionlink = str(baseurl+str('subnets/'+sectionid).replace('//','/'))
                        print('''\
Section(s) found, details below:
----------------------------------------------------------------
Section Name:       {0}
Description:        {1}
Master Section:     {2}
Section DNS:        {3}
Last Change:        {4}
Subnets:            {5}
--------------------------------    
Link:               {6}
----------------------------------------------------------------


'''.format(sectionname,sectiondescription,mastersection,sectiondns,lastchange,subnetinfo,sectionlink))
    elif args.object[0]=='ip':
        for ip in args.object:
            if not ip == 'ip': 
                if fun_isip(ip):
                    resp = requests.get(apiurl+'/addresses/search/'+str(ip), headers={'token':str(token)}, verify=False).json()
                    logging.debug(str(resp)+'\n\n\n')
                    if resp['success']:
                        for data in resp['data']:
                            logging.debug('Data:'+str(data))
                            iphostname = data['hostname']
                            iptag = requests.get(apiurl+'/addresses/tags/'+data['tag'], headers={'token':str(token)}, verify=False).json()['data']['type']
                            if data['deviceId'] == None: ipdevice = data['deviceId']
                            else: ipdevice = ''
                            if data['is_gateway']  == '0': ipdefgw = False
                            elif data['is_gateway']  == '1': ipdefgw = True
                            else: ipdefgw = 'Data ERROR'
                            ipdesc =  data['description']
                            ipowner = data['owner']
                            iplastedit = data['editDate']
                            iplastseen = data['lastSeen']
                            ipnote = data['note']
                            subnetinfo = requests.get(apiurl+'/subnets/'+data['subnetId'], headers={'token':str(token)}, verify=False).json()['data']
                            ipsubnet = ipaddress.IPv4Network(str(subnetinfo['subnet'])+'/'+str(subnetinfo['mask']))
                            ipsection = requests.get(apiurl+'/sections/'+subnetinfo['sectionId'], headers={'token':str(token)}, verify=False).json()['data']['name']
                            iplink = baseurl+'/subnets/'+subnetinfo['sectionId']+'/'+data['subnetId']+'/address-details/'+data['id']
                            print('''\
IP Address "{0}" found, details below:
----------------------------------------------------------------
    IP Address:         {0}
    Hostname:           {1}
    Tagged:             {2}
    Device:             {3}
    Is Default Gateway: {4}
    Subnet:             {5}
    Section:            {6}
--------------------------------    
    Description:        {7}
    Owner:              {8}
    Last Edit:          {9}
    Last Seen:          {10}
    Note:               {11}
    Link:               {12}
----------------------------------------------------------------


'''.format(ip,iphostname,iptag,ipdevice,ipdefgw,ipsubnet,ipsection,ipdesc,ipowner,iplastedit,iplastseen,ipnote,iplink))
                else:
                    if ip == 'all':
                        resp = requests.get(apiurl+'/addresses/', headers={'token':str(token)}, verify=False).json()
                        logging.debug(str(resp)+'\n\n\n')
                        if resp['success']:
                            print('Caution! Search result might contain MANY entries. Reading massive data at one time can result in high load and/or issues at IPAM!')
                            answer = input ('Are you sure?y/n\n')
                            if answer == 'n' or answer == 'N':
                                raise SystemExit('Aborted')
                            elif answer == 'y' or answer == 'Y':
                                pass
                            else:
                                raise SystemExit('Aborted - invalid answer')
                            for data in resp['data']:
                                logging.debug('Data:'+str(data))
                                iphostname = data['hostname']
                                iptag = requests.get(apiurl+'/addresses/tags/'+data['tag'], headers={'token':str(token)}, verify=False).json()['data']['type']
                                if data['deviceId'] == None: ipdevice = data['deviceId']
                                else: ipdevice = ''
                                if data['is_gateway']  == '0': ipdefgw = False
                                elif data['is_gateway']  == '1': ipdefgw = True
                                else: ipdefgw = 'Data ERROR'
                                ipdesc =  data['description']
                                ipowner = data['owner']
                                iplastedit = data['editDate']
                                iplastseen = data['lastSeen']
                                ipnote = data['note']
                                subnetinfo = requests.get(apiurl+'/subnets/'+data['subnetId'], headers={'token':str(token)}, verify=False).json()['data']
                                ipsubnet = ipaddress.IPv4Network(str(subnetinfo['subnet'])+'/'+str(subnetinfo['mask']))
                                ipsection = requests.get(apiurl+'/sections/'+subnetinfo['sectionId'], headers={'token':str(token)}, verify=False).json()['data']['name']
                                iplink = baseurl+'/subnets/'+subnetinfo['sectionId']+'/'+data['subnetId']+'/address-details/'+data['id']
                                print('''\
IP Address "{0}" found, details below:
----------------------------------------------------------------
IP Address:         {0}
Hostname:           {1}
Tagged:             {2}
Device:             {3}
Is Default Gateway: {4}
Subnet:             {5}
Section:            {6}
--------------------------------    
Description:        {7}
Owner:              {8}
Last Edit:          {9}
Last Seen:          {10}
Note:               {11}
Link:               {12}
----------------------------------------------------------------


'''.format(data['ip'],iphostname,iptag,ipdevice,ipdefgw,ipsubnet,ipsection,ipdesc,ipowner,iplastedit,iplastseen,ipnote,iplink))
    elif args.object[0]=='nameservers':
        logging.debug(str(args.object)+'\n\n')
        if len(args.object)==1:
            # show nameservers --> show all
            logging.debug(str(requests.get(apiurl+'/tools/nameservers/', headers={'token':str(token)}, verify=False).json())+'\n\n')
            nsdata = requests.get(apiurl+'/tools/nameservers/', headers={'token':str(token)}, verify=False).json()
            print('''Found {0} Nameserver objects:'''.format(len(nsdata)))
            for ns in nsdata['data']:
                print('''
----------------------------------------------------------------
ID:             {0}
Name:           {1}
Name Servers:   {2}
'''.format(ns['id'],ns['name'],ns['namesrv1'].split(';')))
        else:
            for obj in args.object[1:]:
                if fun_isnumber(obj):
                    resp = requests.get(apiurl+'/tools/nameservers/'+str(obj), headers={'token':str(token)}, verify=False).json()
                    if resp['success']:print('''Found Nameserver object:
----------------------------------------------------------------
ID:             {0}
Name:           {1}
Name Servers:   {2}
'''.format(resp['data']['id'],resp['data']['name'],resp['data']['namesrv1'].split(';')))
                    else:
                        raise SystemExit('It seems that no Nameservers object with given ID has been found. If it is not known try "show nameservers"')
                else:
                    raise SystemExit('Please enter valid Nameservers ID. If none is known try "show nameservers"')
    else:
        raise SystemExit('"object" not supported, please use "ip, network, vlan or section"')

#planned
def funcreate(args):
    if args.object[0]=='subnet':
        # Validate the network given is valid
        if fun_isipnetwork(args.object[1]):
            pass

        else:
            print(str(args.object[1])+' is not a valid network!')
            raise SystemExit
        # Check if network already exist
        if requests.get(apiurl+'/subnets/search/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()['code']!=404:
            print('Failure! It looks like the network '+str(args.object[1])+' is already present')
            raise SystemExit
        # setting up necessary attributes for network objects
        print(args.object)

def funsearch(args,token):
    if args.object[0]=='host':
        resp = requests.get(apiurl+'/addresses/search_hostname/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()
        if resp['success']:
            for host in resp['data']:
                hostid = host['id']
                hostsubnetinfo = requests.get(apiurl+'/subnets/'+host['subnetId'], headers={'token':str(token)}, verify=False).json()['data']
                hostsection = requests.get(apiurl+'/sections/'+hostsubnetinfo['sectionId'], headers={'token':str(token)}, verify=False).json()['data']['name']
                subnet = ipaddress.IPv4Network(str(hostsubnetinfo['subnet'])+'/'+str(hostsubnetinfo['mask']))
                hosttag = requests.get(apiurl+'/addresses/tags/'+host['tag'], headers={'token':str(token)}, verify=False).json()['data']['type']
                if host['deviceId'] == None: 
                    hostdevice = str(host['deviceId'])
                    hostdevicename = hostdevice
                    hostdeviceip = hostdevice
                    hostdevicelink = hostdevice
                else: 
                    hostdeviceinfo = requests.get(apiurl+'/devices/'+host['deviceId'], headers={'token':str(token)}, verify=False).json()['data']
                    hostdevicename = hostdeviceinfo['hostname']
                    hostdeviceip = hostdeviceinfo['ip']
                    hostdevicelink = str(baseurl+str('/tools/devices/'+host['deviceId']).replace('//','/'))
                hostlink = str(baseurl+str('/subnets/'+hostsubnetinfo['sectionId']+'/'+host['subnetId']+'/address-details/'+hostid+'/').replace('//','/'))
            print('''\
IP Address "{0}" found, details below:
----------------------------------------------------------------
IP Address:         {1}
Hostname:           {0}
Tag:                {2}
Device:             {3}
    Link:           {4}
Is Default Gateway: {5}
Subnet:             {6}
Section:            {7}
Description:        {8}
Owner:              {9}
Last Edit:          {10}
Last Seen:          {11}
Link:               {12}
----------------------------------------------------------------


'''.format(host['hostname'],host['ip'],hosttag,hostdevicename+' ('+hostdeviceip+')',hostdevicelink,host['is_gateway'],subnet,hostsection,host['description'],host['owner'],host['editDate'],host['lastSeen'],hostlink))
        else:
            print('Hostname not found!')

def funset(args,token):
    if args.object[0]=='network':
        # validating args
        if fun_isnumber(args.object[1]) and fun_isnumber(args.object[3]):
            if args.object[2] == 'nameservers' and fun_isvalidid(args.object[2],args.object[3]) and fun_isvalidid(args.object[0],args.object[1]):
                # set nameservers for network
                resp = requests.patch(apiurl+'/subnets/'+args.object[1], headers={'token':str(token)}, verify=False, data = {'nameserverId':args.object[3]}).json()
                if resp['code']==200:
                    print('''OK, set new Nameserver {0} to Network {1}'''.format(requests.get(apiurl+'/tools/nameservers/'+str(args.object[3]), headers={'token':str(token)}, verify=False).json()['data']['namesrv1'], requests.get(apiurl+'/subnets/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()['data']['subnet']+'/'+str(requests.get(apiurl+'/subnets/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()['data']['mask'])))
                else:
                    print('Something went wrong - Server response: '+str(resp))
            elif args.object[2] == 'name':
                pass
            #planned
            elif args.object[2] == 'nameservers':
                pass
            #planned
            elif args.object[2] == 'device':
                pass
            #planned
        elif args.object[2] == 'type' and fun_isipnetwork(args.object[1]):
            id = fun_getidof('network',args.object[1])
            resp = requests.patch(apiurl+'/subnets/'+str(id), headers={'token':str(token)}, verify=False, data = {'custom_Type':args.object[3]}).json()
            network = str(requests.get(apiurl+'/subnets/'+str(id), headers={'token':str(token)}, verify=False).json()['data']['subnet']+'/'+str(requests.get(apiurl+'/subnets/'+str(id), headers={'token':str(token)}, verify=False).json()['data']['mask']))
            if resp['code'] == 200:
                print('OK - set field {0} for network {1} to "{2}"'.format(str(args.object[2]), str(network), str(args.object[3])))
            else:
                print('Encountered an error - response: {0}. \nEnsure you entered the correct value for custom field.'.format(str(resp)))
            
        elif args.object[2] == 'type' and fun_isvalidid(args.object[0],args.object[1]):
            resp = requests.patch(apiurl+'/subnets/'+args.object[1], headers={'token':str(token)}, verify=False, data = {'custom_Type':args.object[3]}).json()
            network = str(requests.get(apiurl+'/subnets/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()['data']['subnet']+'/'+str(requests.get(apiurl+'/subnets/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()['data']['mask']))
            if resp['code'] == 200:
                print('OK - set field {0} for network {1} to "{2}"'.format(str(args.object[2]), str(network), str(args.object[3])))
            else:
                print('Encountered an error - response: {0}. \nEnsure you entered the correct value for custom field.'.format(str(resp)))
            
            #elif args.object[2] == 'device':
                # for setting custom_fields
        elif fun_isipnetwork(args.object[1]) and fun_isnumber(args.object[3]):
            netid = fun_getidof('network',args.object[1])
            logging.debug(str(netid)+'\n\n')
            resp = requests.patch(apiurl+'/subnets/'+str(netid), headers={'token':str(token)}, verify=False, data = {'nameserverId':args.object[3]}).json()
            logging.debug(str(resp)+'\n\n')
            if resp['code']==200:
                print('''OK, set new Nameservers {0} to Network {1}'''.format(requests.get(apiurl+'/tools/nameservers/'+str(args.object[3]), headers={'token':str(token)}, verify=False).json()['data']['namesrv1'], str(args.object[1])))
            else:
                print('Something went wrong - Server response: '+str(resp))
        pass
    elif args.object[0]=='device':
        pass
    elif args.object[0]=='ip':
        pass
    elif args.object[0]=='nameservers':
        if not fun_isnumber(args.object[1]):
            fun_getidof('nameservers',args.object[0])
        requests.get(apiurl+'/tools/nameservers/'+str(args.object[0]), headers={'token':str(token)}, verify=False).json()
    pass

def fun_isip(ipcandidate):
    try:
        ipaddress.IPv4Address(ipcandidate)
    except:
        ipcandidate=''
        return False
    else:
        ipcandidate=''
        return True

def fun_isipnetwork(ipcandidate):
    try:
        ipaddress.ip_network(ipcandidate)
    except:
        ipcandidate=''
        return False
    else:
        ipcandidate=''
        return True

def fun_isnumber(val):
    # returns True or False, if val is a number
    try:
        float(val)
        return True
    except ValueError:
        val = ''
        return False

def fun_isvalidid(type,id):
    # returns True if object was found, exiting program else
    if type == 'ip': url = apiurl+'/addresses/'+str(id)
    elif type == 'network': url = apiurl+'/subnets/'+str(id)
    elif type == 'section': url = apiurl+'/sections/'+str(id)
    elif type == 'nameservers': url = apiurl+'/tools/nameservers/'+str(id)
    a=requests.get(url,headers={'token':str(token)}, verify=False).json()
    if a['success']:
        return True
    elif a['code']=='401':
        raise SystemExit('Got "not authorized" please check permissions!')
    else:
        raise SystemExit('not a valid id. got response {0} when looking for id {1} '.format(a['code'],id))
    
def fun_getidof(type,name):
    # fetching i.e. all networks, devices etc. for name and return appropriate id, if unique
    # returns True if object was found, exiting program else
    id = []
    if type == 'ip':
        url = apiurl+'/addresses/search'+str(name)
        a=requests.get(url,headers={'token':str(token)}, verify=False).json()
        if a['success']: 
            for a in a['data']:
                if a['name'] == name: id.append(a['id'])
        if len(id) >1:raise SystemExit('Found multiple matching objects! IDs are: '+str(id))
        elif len(id) == 0:raise SystemExit('None found for search string: '+str(name))
        elif len(id) ==1: return id
        else: raise SystemExit('Something happened - undefined')

    elif type == 'network': 
        if fun_isipnetwork(name):
            url = apiurl+'/subnets/cidr/'+str(name)
            a=requests.get(url,headers={'token':str(token)}, verify=False).json()
            logging.debug(a)
            if a['success']: 
                if len(a['data']) == 1:
                    return a['data'][0]['id']
                elif len(a['data']) > 1:
                    for a in a['data']:
                        id.append(a['id'])
                    raise SystemExit('Found multiple matching objects! IDs are: {0} \nTry "show network <id>" to identify the correct'.format(str(id)))
                else: raise SystemExit('None found for search string: '+str(name))
            else: raise SystemExit('Encountered a problem, please check input and/or debug')
        else:
            url = apiurl+'/subnets/'+str(name)
            a=requests.get(url,headers={'token':str(token)}, verify=False).json()
            logging.debug(a)
            if a['success']: 
                for a in a['data']:
                    if a['name'] == name: id.append(a['id'])
        if len(id) >1:raise SystemExit('Found multiple matching objects! IDs are: '+str(id))
        elif len(id) == 0:raise SystemExit('None found for search string: '+str(name))
        elif len(id) ==1: return id
        else: raise SystemExit('Something happened - undefined')

    elif type == 'section': url = apiurl+'/sections/'+str(name)
    elif type == 'nameservers': url = apiurl+'/tools/nameservers/'+str(name)
    return id


if __name__ == "__main__":
    if args.verbose:logging.basicConfig(level=logging.DEBUG)
    logging.debug(args)
    if args.cmd=='show':
        funshow(args,token)
    elif args.cmd=='create':
        funcreate(args,token)
    elif args.cmd=='search':
        funsearch(args,token)
    elif args.cmd=='set':
        funset(args,token)
