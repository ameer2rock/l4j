import requests
import json
from urllib.parse import urlparse, parse_qs
import urllib3
from math import ceil
import OAuthBrowser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import math
import json
import re
import os
import subprocess
import csv

# Constants
pageSize=1000
outputFile="plb_l4j_vulns.csv"
duck_api = 'https://redmediation.site'
l4jString="formatMsgNoLookups=true"
totalOpVulns = 0
totalChecked = 0
clusters={}
# pulled these from working browser session; all may not be required, but it works
oauthHeader={
'scheme': 'https',
'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'accept-encoding': 'gzip, deflate, br',
'accept-language': 'en-US,en;q=0.9',
'cache-control': 'max-age=0',
'referer': 'https://login.microsoftonline.com/',
'sec-ch-ua': 'Not A;Brand";v="99","Chromium";v="96","Google Chrome";v="96"',
'sec-ch-ua-mobile': '?0',
'sec-ch-ua-platform': "macOS",
'sec-fetch-dest': 'document',
'sec-fetch-mode': 'navigate',
'sec-fetch-site': 'cross-site',
'sec-fetch-user': '?1',
'upgrade-insecure-requests': '1',
'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
}

def checkKey(dict, key):
    if key in dict.keys():
        return 1
    else:
        return 0

def generate_params(page):
    p={
        'cve': 'CVE-2021-44228',
        'page': page,
        'page_size': pageSize
    }
    return p

def return_vuln_data(api,params):
    # as I understand it; the authorization is keyed to the exact URI; meaning each call requires a new session and bearer code
    # trying to generate a token for the naked URL (no CVE data) doesn't work, and subsequent calls with a working code to a slightly different
    # URI (page=2 for example) fails with a 401.
    s=requests.session()
    # returns the redrirect URL for MS OAuth login; sets a cookies with session id that is used to track this auth to duck api
    #redirectCall=s.get(duck_api,verify=False,headers=oauthHeader,params=generate_params(1),allow_redirects=False)
    redirectCall=s.get(duck_api,verify=False,headers=oauthHeader,params=params,allow_redirects=False)
    cookie = redirectCall.cookies
    oauthUrl=redirectCall.headers["location"]
    # Initialise browser
    browser = OAuthBrowser.Chrome(window_geometry=(100, 22, 400, 690))
    # Pass Authentication URL
    browser.open_new_window(oauthUrl)
    # Initialise Wait
    wait = OAuthBrowser.Wait(browser)
    # Wait till query "code" is present in the URL.  This code has to be sent to the /authorize redirect back on prem.
    wait.until_present_query('code')
    # Fetch the url
    responseUrl = urlparse(browser.get_current_url())
    # take the url parse object and create the redirect URI and query parms with the code and session
    # post_token_url
    authcodeUrl="https://" + responseUrl[1] + responseUrl[2]
    aryOauth = responseUrl[4].split('&')
    # done with browser; this closes all of Chrome
    browser.quit()
    # load object for bearer params from urlparse object
    authcodeParams={}
    for authquery in aryOauth:
        key,value = authquery.split('=')
        authcodeParams[key]=value

    # Docs say this should be a POST; however doing it with a browser was a get with params set
    # the params include the oauth Code; which verifies the session stored in the cookie from the web server
    vulnData=s.get(authcodeUrl,verify=False,params=authcodeParams,cookies=cookie,headers=oauthHeader)
    payload=json.loads(vulnData.content)
    return payload

def load_vuln_dict(data):
    global totalOpVulns
    global totalChecked
    totalChecked=totalChecked+1
    clusterName=(data["cluster_name"])
    # if cluster starts with onprem; load it; otherwise ignore it
    vulnData={}
    if re.match('^px',clusterName) or re.match('^tt',clusterName):
        vulnData["name"]=data["name"]
        vulnData["namespace"]=data["namespace"]
        vulnData["deployment"]=data["deployment"]
        if checkKey(clusters,clusterName):
            clusters[clusterName].append(vulnData)
            totalOpVulns=totalOpVulns+1
        else:
            # cluster doesnt exist yet
            newCluster=[]
            newCluster.append(vulnData)
            clusters[clusterName]=newCluster
            totalOpVulns=totalOpVulns+1
    else:
        # ignore things not on prem
        pass

# https://api.csp-apis-duck-prd-w2.kube.t-mobile.com/api/v1/pods/cves?cve=CVE-2021-44228&page=1
# https://api.csp-apis-duck-plb-w2.kube.t-mobile.com/api/v1/pods/cves?cve=CVE-2021-44228&page=1
# https://api.csp-apis-duck-prd-w2.kube.t-mobile.com/api/v1/pods/cves?cve=CVE-2021-44228&page_size=100&page=5
# duck_api = "https://api.csp-apis-duck-prd-w2.kube.t-mobile.com/api/v1/pods/cves?cve=CVE-2021-44228&page=1"
'''
csv structure:
[was javaops found; then did it contain the string]
[error; couldnt get env]
api_url,cluster,namespace,deployment,name,javaops,l4jstring,error
'''

"""
Redirect URL:
https://login.microsoftonline.com/be0f980b-dd99-4b19-bd7b-bc71a09b026c/oauth2/authorize?response_type=code&client_id=7f51ade1-9fd3-4fa7-b7b7-4f1bbe473b94%0A&redirect_uri=https://api.csp-apis-duck-prd-w2.kube.t-mobile.com/authorized&state=P3TQGHWTOI3PR12PPF4TP0L9GHTGPAVUN4DCKTN69PKQRIX8&resource=00000002-0000-0000-c000-000000000000
"""

# get the total item count
print("Getting first batch")
firstpageParams=generate_params(1)
firstpageData=return_vuln_data(duck_api,firstpageParams)
totalCount=firstpageData["count"]
print("Total vulnerabilities listed in: " + str(totalCount))
try:
    for vuln in firstpageData["result"]:
        load_vuln_dict(vuln)
except:
    print("failed to load: " + str(vuln))
    exit(1)

# determine the remaining page counts to load
# round up to the next integer; the last batch returns all that are left; even with batch set to 1000
batches= math.ceil(totalCount/pageSize)
# start at 2nd batch as we already have the 1st page loaded into vulnData
for page in range(2,batches+1):
    print("Getting batch " + str(page))
    pageParams=generate_params(page)
    pageData=return_vuln_data(duck_api,pageParams)
    try:
        for vuln in pageData["result"]:
            load_vuln_dict(vuln)
    except:
        print("failed to load: " + str(vuln))
        exit(1)
print("Total clusters: " + str(len(clusters)))
print("Total Onprem items: " + str(totalOpVulns))
print("Total items (should match totalCount): " + str(totalChecked))
print("Working on clusters:")
for cn in clusters.keys():
    print(cn)

# Set up output file
with open(outputFile, 'a', newline='') as csvfile:
    fieldnames = ['api_url','cluster','namespace','deployment','name','javaops','l4jstring','error']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for key in clusters.keys():
        print("Starting cluster: " + key)
        os.system("tke login -e " + key)
        clusterPods = clusters[key]
        # k exec -n omni-legacy -it  omni-blue-deployment-0 -- 'printenv' | grep -i formatMsgNoLookups=true
        for pods in clusterPods:
            print("Starting pod: " + pods["name"])
            #print("k exec -n " + pods["namespace"] + " -it " + pods["name"] + " -- 'printenv' | grep -q formatMsgNoLookups=true")
            #envalue=os.system("/usr/local/bin/kubectl exec -n " + pods["namespace"] + " -it " + pods["name"] + " -- 'printenv' ") #| grep -i formatMsgNoLookups=true")
            #k exec -n omni-legacy -it omni-blue-deployment-0 -- 'printenv'
            cmdargs=[]
            cmdargs.append("/usr/local/bin/kubectl")
            cmdargs.append("exec")
            cmdargs.append("-n")
            cmdargs.append(pods["namespace"])
            cmdargs.append("-it")
            cmdargs.append(pods["name"])
            cmdargs.append("--")
            cmdargs.append("printenv")
            #,pods["namespace"],"-it",pods["name"], "--","printenv"
            #envalue=subprocess.run(["/usr/local/bin/kubectl", "exec", "-n ",pods["namespace"],"-it",pods["name"], "--","printenv" ],capture_output=True,check=True)
            JO_SET=0
            L4J=0
            try:
                envalue=subprocess.run(cmdargs,capture_output=True,check=True)
                envalueStdoutDecode=envalue.stdout.decode('utf-8')
                if re.search("JAVA_OPTS=",envalueStdoutDecode,re.IGNORECASE):
                    print("JAVA_OPTS set")
                    JO_SET=1
                if re.search(l4jString,envalueStdoutDecode,re.IGNORECASE):
                    print("l4j set")
                    L4J=1
                ERROR="False"
            except:
                ERROR="True"
            CLUSTER=key
            NS=pods["namespace"]
            DP=pods["deployment"]
            NAME=pods["name"]
            if JO_SET == 1:
                JO="True"
            else:
                JO="False"
            if L4J == 1:
                L4JSTR="True"
            else:
                L4JSTR="False"
            writer.writerow({'api_url': duck_api,'cluster': CLUSTER,'namespace': NS,'deployment': DP,'name': NAME,'javaops': JO,'l4jstring': L4JSTR,'error': ERROR })
csvfile.close()
exit(0)
