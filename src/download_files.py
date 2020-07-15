from os.path import exists, isfile, join
from os import listdir
from unzip import make_cve_csv
from datetime import datetime, timedelta
import requests
import re
import os


# Downloads CVE for given year, or all CVE
def download_files(source, year):

    last_year = datetime.today().year

    if source == 'cve' and year == 'update':
        if exists('nvd') and listdir('nvd'):
            
            files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
            files.sort()

            for file in files:
                x = re.findall('nvdcve-1.1-[0-9]*', file)
                year = x[0][-4:]
                
                download_files('cve', year)
            
            make_cve_csv()
            print('Updated cve.')

        else:
            print('''You need to have data in order to update it.
To download data use "fidelio -d [SOURCE] [YEAR]"''')

    elif source == 'cve' and (year == 'all' or int(year) in range(2002, last_year+1)):
        r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
        # print(r.text)
        
        try:
            os.mkdir('nvd')
            print("Directory nvd Created ") 
        except FileExistsError:
            print("Directory nvd already exists")  
            

        file_link = "\.json\.zip" if year == 'all' else f"nvdcve-1.1-{year}\.json\.zip"
        for filename in re.findall(file_link, r.text):
            
            r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename,
                                stream=True)

            with open(os.getcwd() + "/nvd/" + filename, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)
            print(f'Downloaded {filename}')

    elif source == 'cpe' and year == 'all':
        r = requests.get('https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip')
        
        try:
            os.mkdir('cpe')
            print("Directory cpe Created ") 
        except FileExistsError:
            print("Directory cpe already exists")
        print(f'Downloaded official-cpe-dictionary_v2.3.xml.zip')

        open(os.getcwd() + '/cpe/official-cpe-dictionary_v2.3.xml.zip', 'wb').write(r.content)
    
    elif source != 'cpe' and source != 'cve':
        print("Argument not recognized: SOURCE (try 'cve' or 'cpe')")
    
    elif source == 'cpe' and year != 'all':
        print("Second argument for SOURCE='cpe' can only be 'all'")
    
    elif source == 'cve' and int(year) not in range(2002,2020):
        print("Argument not recognized: YEAR (try 2002-2020)")
    

