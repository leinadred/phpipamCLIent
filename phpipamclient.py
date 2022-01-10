# Daniel Meier
# import modules
import urllib3
import argparse
import logging
import requests
import ipaddress
import json
import getpass
urllib3.disable_warnings()

#######################################################################################################

#######################################################################################################
baseurl = 'https://phpipam.asd.fg/'         # put in PHPIPAM URL (http(s)://hostname-or-fqdn/)
appid = 'ipamCLIent'                                # AppID (configured at API mnu)
apiusername = ''                                    # if auth is set to "User token"
apiuserpass = ''                                    # if auth is set to "User token"    
apitoken = ''                                       # if auth is set to "App roken"
#######################################################################################################

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='extended logging')
parser.add_argument('-a', '--appid', help='set AppID ( overrides the app id set in scriptfile)')
parser.add_argument('-k', '--key', help='API Key (overrides Settings in script file)')
parser.add_argument('-u', '--baseurl', help='PHPIPAM Base URL (ie http://phpipam.asd.fg - overrides Settings in script file)')

subparser = parser.add_subparsers(required=True, dest='cmd', help='Tell what to do (show||search||create||edit)')

# show known network 
parser_show = subparser.add_parser('show')
parser_show.add_argument('object', nargs='*', type=str, default=None, help='object to show / edit /create - "show network 10.0.0.0/8 192.168.100.0/24" (currently supported: network | vlan | section)')

#parser_show.set_defaults(func=funshow)

# search command (when network is not known - i.e. search in Description)
parser_search = subparser.add_parser('search')
parser_search.add_argument('object', nargs='*', type=str, default=None, help='search network (use CIDR notation) multiple possible - for example "subnet(CIDR)" or "vlanID"')
#parser_search.set_defaults(func=funsearch)

# create command (currently not implemented yet)
#parser_create = subparser.add_parser('add')
#parser_search.add_argument('object', nargs='*', type=str, default=None, help='search network (use CIDR notation) multiple possible - for example "subnet(CIDR)" or "vlanID"')

# parse the args and call whatever function was selected
args = parser.parse_args()


if args.verbose:logging.basicConfig( level=logging.DEBUG)

# overriding preset values with arguments
if args.appid != None: appid = args.appid
if args.key: apitoken = args.key
if args.baseurl: baseurl = args.baseurl
logging.debug('Setup: \nBase URL: '+baseurl+'\nApp ID: '+appid+'\nAPITOKEN '+apitoken)
if baseurl[-1] == '/': apiurl = baseurl+'api/'+appid
else: apiurl = baseurl+'/api/'+appid               # creating URL to API Application
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
            raise Exception('Got "'+str(authresult)+'" - Response Code - check auth settings at phpipam or values entered')
else:
    token = requests.post(apiurl+'/user', auth=(apiusername, apiuserpass), verify=False).json()['data']['token']
logging.debug('auth Done - token: '+token)
apiusername=''; apiuserpass=''; apitoken=''

#######################################################################################################
# Functions
def funshow(args,token):
    logging.debug(args)
    if args.object[0]=='network':
        logging.debug(args.object)
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


'''.format(section,subnet,subnetdesc,nameserversn+' {'+nameserverss+'}',subnetmaster,str(vlanid), str(vlanname),str(vlandom),subnetedit,subnetscandisc,baseurl+'subnets/'+str(result['sectionId'])+'/'+str(result['id'])))
                        section='';subnet='';vlanid = '';subnetdesc='';nameserverss = ''; nameserversn = '';vlanname = ''; vlandom = ''; subnetedit = '';subnetscandisc = ''
                else: print('Network "{}" not found or not authorized!'.format(subnet))
            vlanid = ''; vlanname = ''; vlandom = ''; nameserverss = ''; nameserversn = ''; section = ''
            
    elif args.object[0]=='vlan':
        logging.debug(args.object)
        for vlan in args.object:
            if not vlan == 'vlan':
                resp = requests.get(apiurl+'/vlan/search/'+vlan, headers={'token':str(token)}, verify=False).json()
                logging.debug(str(resp)+'\n\n\n')
                if resp['success']:
                    for data in resp['data']:
                        logging.debug('Data:'+str(data))
                        vlanid = data['vlanId']
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


'''.format(vlansection,vlancustomer,vlanid,vlandomain,vlanname,vlandesc,vlansubnet,vlanlink))

        logging.debug(args.object)
        pass
    elif args.object[0]=='section':
        logging.debug(args.object)
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
    if args.object[0]=='ip':
        logging.debug(args.object)
        for ip in args.object:
            if not ip == 'ip': 
                try:
                    ipaddress.IPv4Address(ip)
                except:
                    if ip == 'all':
                        resp = requests.get(apiurl+'/addresses/', headers={'token':str(token)}, verify=False).json()
                        logging.debug(str(resp)+'\n\n\n')
                        if resp['success']:
                            print('Caution! Search result contains more than {} entries. Reading massive data at one time can result in high load and/or issues at IPAM!'.format(50))
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
                                iptag = data['tag']
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
                else:    
                    resp = requests.get(apiurl+'/addresses/search/'+str(ip), headers={'token':str(token)}, verify=False).json()
                    logging.debug(str(resp)+'\n\n\n')
                    if resp['success']:
                        for data in resp['data']:
                            logging.debug('Data:'+str(data))
                            iphostname = data['hostname']
                            iptag = data['tag']
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
        raise SystemExit('"object" not supported, please use "network, vlan or section"')
def funcreate(args):
    logging.debug(args)
    if args.object[0]=='subnet':
        # Validate the network given is valid
        try:
            ipaddress.IPv4Network(args.object[1])
        except:
            print(str(args.object[1])+' is not a valid network!')
            raise SystemExit
        # Check if network already exist
        if requests.get(apiurl+'/subnets/search/'+str(args.object[1]), headers={'token':str(token)}, verify=False).json()['code']!=404:
            print('Failure! It looks like the network '+str(args.object[1])+' is already present')
            raise SystemExit
        # setting up necessary attributes for network objects

        print(args.object)

def funsearch():
    pass



if __name__ == "__main__":
    if args.verbose:logging.basicConfig(level=logging.DEBUG)
    if args.cmd=='show':
        funshow(args,token)
    elif args.cmd=='search':
        funsearch(args,token)
    elif args.cmd=='create':
        funcreate(args,token)
