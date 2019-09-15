#Class containing the default config
class domainDumpConfig():
    def __init__(self):
        #Base path
        self.basepath = '.'

        #Output files basenames
        self.groupsfile = 'domain_groups' #Groups
        self.usersfile = 'domain_users' #User accounts
        self.computersfile = 'domain_computers' #Computer accounts
        self.policyfile = 'domain_policy' #General domain attributes
        self.trustsfile = 'domain_trusts' #Domain trusts attributes

        #Combined files basenames
        self.users_by_group = 'domain_users_by_group' #Users sorted by group
        self.computers_by_os = 'domain_computers_by_os' #Computers sorted by OS

        #Output formats
        self.outputhtml = True
        self.outputjson = True
        self.outputgrep = True

        #Output json for groups
        self.groupedjson = False

        #Default field delimiter for greppable format is a tab
        self.grepsplitchar = '\t'

        #Other settings
        self.lookuphostnames = False #Look up hostnames of computers to get their IP address
        self.dnsserver = '' #Addres of the DNS server to use, if not specified default DNS will be used
