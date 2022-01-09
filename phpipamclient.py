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

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='extended logging')
subparser = parser.add_subparsers(required=True, dest='cmd', help='Tell what to do (show||search||create||edit)')

# show known network 
parser_show = subparser.add_parser('show')
parser_show.add_argument('object', nargs='*', type=str, default=None, help='object to show / edit /create - "show subnet 10.0.0.0/8 192.168.100.0/24"')

#parser_show.set_defaults(func=funshow)

# search command (when network is not known - i.e. search in Description)
parser_search = subparser.add_parser('search')
parser_search.add_argument('object', nargs='*', type=str, default=None, help='search subnet (use CIDR notation) multiple possible - for example "subnet(CIDR)" or "vlanID"')
#parser_search.set_defaults(func=funsearch)

# create command
parser_create = subparser.add_parser('create')
parser_create.add_argument('--subnet', type=str, required=True, help='(CIDR notated) network to create')
parser_create.add_argument('--section', type=str, required=True, help='section to create the network object in')
parser_create.add_argument('--desc', type=str, required=True, help='description of network object')
parser_create.add_argument('--master', type=str, required=True, help='master subnet/folder')
parser_create.add_argument('--vlan', type=str, required=False, help='VLAN to be linked with')
parser_create.add_argument('--nameserver', type=str, required=True, help='nameserver set to resolve network')

#parser_create.set_defaults(func=funcreate)

args = parser.parse_args()
# parse the args and call whatever function was selected
#args = parser.parse_args()

#######################################################################################################
baseurl = ''         # put in PHPIPAM URL (http(s)://hostname-or-fqdn/)
appid = ''                                # AppID (configured at API mnu)
apiusername = ''                                    # if auth is set to "User token"
apiuserpass = ''                                    # if auth is set to "User token"    
apitoken = ''                                       # if auth is set to "App roken"
apiurl = baseurl+'/api/'+appid                      # creating URL to API Application
#######################################################################################################

if args.verbose:logging.basicConfig( level=logging.DEBUG)

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
            if requests.post(apiurl+'/sections/0', headers={'token':apiuserpass}, verify=False).json()['code'] != 200:
                raise Exception('Unauthorized - check auth settings at phpipam or values entered')
            else:
                token = apiuserpass
        else: print('something went wrong, please try again or check script / auth settings')
    else:
        if requests.post(apiurl+'/sections/0', headers={'token':apiuserpass}, verify=False).json()['code'] != '401':
            token = apiuserpass
        else: 
            raise Exception('Got "401" Response Code - Unauthorized - check auth settings at phpipam or values entered')
else:
    token = requests.post(apiurl+'/user', auth=(apiusername, apiuserpass), verify=False).json()['data']['token']
logging.debug('auth Done - token: '+token)
apiusername=''
apiuserpass=''
# Functions
def funshow(args,token):
    logging.debug(args)
    if args.object[0]=='subnet':
        logging.debug(args.object)
        for subnet in args.object:
            if not subnet == 'subnet':
                resp = requests.get(apiurl+'/subnets/search/'+subnet, headers={'token':str(token)}, verify=False)
                logging.debug(resp.text+'\n\n\n')
                if resp.json()['success']:
                    if resp.json()['data'][0]['vlanId'] != None:
                        vlanresp = requests.get(apiurl+'/vlan/'+str(resp.json()['data'][0]['vlanId']), headers={'token':str(token)}, verify=False)
                        vlanid = vlanresp.json()['data']['number']
                        vlanname = vlanresp.json()['data']['name']
                        if vlanresp.json()['data']['domainId'] != 'null':
                            vlandom = requests.get(apiurl+'/l2domains/'+vlanresp.json()['data']['domainId'], headers={'token':str(token)}, verify=False).json()['data']['name']
                    else: vlanid = 'none defined'
                    if resp.json()['data'][0]['nameserverId'] != '0':
                        nameserversn = requests.get(apiurl+'/tools/nameservers/'+str(resp.json()['data'][0]['nameserverId']), headers={'token':str(token)}, verify=False).json()['data']['name']
                        nameserverss = requests.get(apiurl+'/tools/nameservers/'+str(resp.json()['data'][0]['nameserverId']), headers={'token':str(token)}, verify=False).json()['data']['namesrv1']
                    else: nameserversn = 'none defined'
                    logging.debug(resp.text+'\n\n\n')
                    print('''\
Network found, details below:
----------------------------------------------------------------
    Section:            {0}
    Customer:           {1}
    Subnet/Mask:        {2}
    Description:        {3}
    Nameservers:        {4}
    Master Subnet:      {5}
    VLan (VLan Name):   {6} ({7})
    L2 Domain:          {8}
    Owner:              {9}
    Notes:              {10}
--------------------------------    
    Link:               {11}
----------------------------------------------------------------


'''.format('','',str(ipaddress.IPv4Network(str(resp.json()['data'][0]['subnet'])+'/'+str(resp.json()['data'][0]['mask'])).with_netmask),str(resp.json()['data'][0]['description']),nameserversn+' {'+nameserverss+'}','master',str(vlanid), str(vlanname),str(vlandom),'','', baseurl+'subnets/'+str(resp.json()['data'][0]['sectionId'])+'/'+str(resp.json()['data'][0]['id'])))
                else: print('Network "{}" not found or not authorized!'.format(subnet))
            vlanid=''
            vlanname=''
            vlandom=''
            nameserverss=''
            nameserversn=''
            
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
