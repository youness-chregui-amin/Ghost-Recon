import dns.resolver

def get_subdomains(domain, wordlist=None):
    """
    Brute-force subdomains using a wordlist and dnspython. Returns a set of discovered subdomains.
    """
    if wordlist is None:
        # A small default wordlist; in practice, use a larger one or allow user input
        wordlist = [
            'www', 'mail', 'ftp', 'dev', 'test', 'admin', 'portal', 'vpn', 'webmail', 'ns1', 'ns2', 'api', 'staging', 'blog', 'shop', 'm', 'cdn', 'img', 'static', 'beta', 'app', 'secure', 'server', 'gw', 'gateway', 'db', 'mysql', 'sql', 'smtp', 'pop', 'imap', 'cloud', 'files', 'downloads', 'assets', 'docs', 'help', 'support', 'forum', 'news', 'old', 'backup', 'bkp', 'demo', 'new', 'dev1', 'dev2', 'test1', 'test2', 'stage', 'preprod', 'prod', 'production', 'monitor', 'status', 'login', 'auth', 'sso', 'sftp', 'git', 'svn', 'jira', 'confluence', 'ci', 'cd', 'jenkins', 'build', 'ci-cd', 'dashboard', 'monitoring', 'metrics', 'grafana', 'kibana', 'elk', 'log', 'logs', 'logstash', 'elastic', 'elasticsearch', 'search', 'data', 'analytics', 'report', 'reports', 'reporting', 'insight', 'insights', 'metrics', 'metrics-api', 'api1', 'api2', 'api3', 'api4', 'api5', 'api6', 'api7', 'api8', 'api9', 'api10', 'devops', 'pipeline', 'pipelines', 'ci1', 'ci2', 'ci3', 'ci4', 'ci5', 'ci6', 'ci7', 'ci8', 'ci9', 'ci10', 'test-api', 'testapp', 'testsite', 'testweb', 'testserver', 'testdb', 'testmail', 'testftp', 'testvpn', 'testcloud', 'testcdn', 'testimg', 'teststatic', 'testbeta', 'testapp', 'testsecure', 'testserver', 'testgw', 'testgateway', 'testdb', 'testmysql', 'testsql', 'testsmtp', 'testpop', 'testimap', 'testcloud', 'testfiles', 'testdownloads', 'testassets', 'testdocs', 'testhelp', 'testsupport', 'testforum', 'testnews', 'testold', 'testbackup', 'testbkp', 'testdemo', 'testnew', 'testdev1', 'testdev2', 'testtest1', 'testtest2', 'teststage', 'testpreprod', 'testprod', 'testproduction', 'testmonitor', 'teststatus', 'testlogin', 'testauth', 'testsso', 'testsftp', 'testgit', 'testsvn', 'testjira', 'testconfluence', 'testci', 'testcd', 'testjenkins', 'testbuild', 'testci-cd', 'testdashboard', 'testmonitoring', 'testmetrics', 'testgrafana', 'testkibana', 'testelk', 'testlog', 'testlogs', 'testlogstash', 'testelastic', 'testelasticsearch', 'testsearch', 'testdata', 'testanalytics', 'testreport', 'testreports', 'testreporting', 'testinsight', 'testinsights', 'testmetrics', 'testmetrics-api', 'testapi1', 'testapi2', 'testapi3', 'testapi4', 'testapi5', 'testapi6', 'testapi7', 'testapi8', 'testapi9', 'testapi10', 'testdevops', 'testpipeline', 'testpipelines', 'testci1', 'testci2', 'testci3', 'testci4', 'testci5', 'testci6', 'testci7', 'testci8', 'testci9', 'testci10'
        ]
    found = set()
    resolver = dns.resolver.Resolver()
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, 'A')
            found.add(fqdn)
        except Exception:
            continue
    return found 