import requests
import re
import os


# Downloads CVE for given year, or all CVE
def download_cve(year):
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    # print(r.text)
    
    file_link = "nvdcve-1.1-[0-9]*\.json\.zip" if year == 'all' else f"nvdcve-1.1-{year}\.json\.zip"
    for filename in re.findall(file_link, r.text):
        print(filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename,
                            stream=True)
        try:
            os.mkdir('nvd')
            print("Directory nvd Created ") 
        except FileExistsError:
            print("Directory nvd already exists")  

        with open(os.getcwd() + "/nvd/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)

