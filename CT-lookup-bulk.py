# CT-API-request.py
# perform bulk lookup using CyberTrace API 1.1
#
# usage: CT-lookup-bulk.py <file1> [<file_n>]
# 
# Eduardo Chavarro Ovalle - @echavarro
#
# v1

import argparse
import requests
from requests.auth import HTTPBasicAuth
import json
import datetime

user = "youruser"        
password = "yourpassword" 
http_api='https://<CyberTraceURL>/api/1.1/' 

lookup='lookup'
separator='|'

bulk_size=100
DEBUG=0
only_detected=0
output=0

now = datetime.datetime.now()
datefn = 'CT_' + (now.isoformat()).replace(":", "")
     
def handleRequest(payload) :
  try:
    headers={"Accept": "application/json",}
    p = requests.post(http_api+lookup, json=payload, auth=HTTPBasicAuth(user, password), headers=headers)
    if p.status_code == 200:
       handleAnswer(p)
    return p
  except:
    print ("error " + str(p.status_code))
    exit(-1)

def handleAnswer(resp) :
    r = json.loads(resp.text)
    if DEBUG: print(r)
    for entry in r:
      try:
        obj=entry["object"]
        verd=entry["result"]
        cats=entry["categories"]
        if output:
            savetofile(obj + separator + verd + separator + str(cats))
        else:
            print(obj + separator + verd + separator + str(cats))
      except:
        if only_detected!=1:
            if output:
                savetofile(obj + separator + verd + separator)
            else:
                print(obj + separator + verd + separator)

def LoadFromFile(ifile,ilist):
    try:
        with open(ifile, 'r') as i_f:
            content=i_f.read()
            for each in content.splitlines():
                if each != '' : ilist.append(each)
    except:
        print('Error loading file %s' % file)
        exit(-1)

def savetofile(myline):
    try:
        with open(datefn + '.log', 'a') as f:
                f.write(myline + '\n')
    except:
        print('Error saving file ' + datefn)
        exit(-1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description='Perform requests to CyberTrace using REST API')
    parser.add_argument('input_ioc', help="one or more IoC to look Up", nargs='+')
    parser.add_argument('-f', '--input_is_file',  action="store_true", default=None, help="input is/are files (one IoC for line)")
    parser.add_argument('-o', '--output', help="Output results to file CT_<date>.log", action="store_true")
    parser.add_argument('-d', '--detections', help="Register only IoCs with detection results", action='store_true')
    args = parser.parse_args()
    ioclist=[]
    if args.input_is_file:
        for file in args.input_ioc:
            LoadFromFile(file,ioclist)
    else:
        ioclist=args.input_ioc

    if args.detections:
        only_detected=1

    if args.output:
        output=1
        print('Results will be saved to file ' + datefn + '.log')
        savetofile('IoC'+separator+'Result'+separator+'Categories'+'\n')

    i=0
    payload=[]
    for ioc in ioclist:

      if i<bulk_size:
        val=ioc.strip().lower().replace('http://','').replace('https://','').replace('//','/').replace('^www.','')
        payload.append({ "object": val})
        i+=1

      if i==bulk_size:
        p=handleRequest(payload)
        i=0
        payload=[]

    if i!=0:
        p=handleRequest(payload)
    exit(0)

        
