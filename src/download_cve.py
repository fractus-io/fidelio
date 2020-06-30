import requests
import re
import os


# Downloads CVE for given year, or all CVE
def download_cve(source, year):

    if source == 'cve' and (int(year) in range(2002,2021)):
        r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
        # print(r.text)
        
        file_link = "nvdcve-1.1-[0-9]*\.json\.zip" if year == 'all' else f"nvdcve-1.1-{year}\.json\.zip"
        for filename in re.findall(file_link, r.text):
            
            r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename,
                                stream=True)
            try:
                os.mkdir('nvd')
                print("Directory nvd Created ") 
            except FileExistsError:
                print("Directory nvd already exists")  
            print(f'Downloaded {filename}')

            with open(os.getcwd() + "/nvd/" + filename, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)

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
        print("Second argument for SOURCE='cve' can only be 'all'")
    
    elif source == 'cve' and int(year) not in range(2002,2020):
        print("Argument not recognized: YEAR (try 2002-2020)")
    

