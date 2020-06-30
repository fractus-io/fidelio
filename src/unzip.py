from os import listdir
from os.path import isfile, join
from zipfile import ZipFile
import xml.etree.ElementTree as et
import json


# unzips CVEs and returns a list with information
def unzipJson():
    
    cve_list = []    
    files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
    files.sort()
    # print(files)

    num = 0

    for file in files:
        # print(join("nvd/", file))

        archive = ZipFile(join("nvd/", file), 'r')

        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())

        for cve in cve_dict.get('CVE_Items'):
            try:
                cweid = cve['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
                vector = cve['impact']['baseMetricV2']['cvssV2']['vectorString']
                availability_impact = cve['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
                integrity_impact = cve['impact']['baseMetricV2']['cvssV2']['integrityImpact']
                confidentiality_impact = cve['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
                authentication = cve['impact']['baseMetricV2']['cvssV2']['authentication']
                access_complexity = cve['impact']['baseMetricV2']['cvssV2']['accessComplexity']
                access_vector = cve['impact']['baseMetricV2']['cvssV2']['accessVector']
                exploit = float(cve['impact']['baseMetricV2']['exploitabilityScore'])
                impact = float(cve['impact']['baseMetricV2']['impactScore'])
                base = float(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
                summary = cve['cve']['description']['description_data'][0]['value']
                mod_date = cve["lastModifiedDate"]
                pub_date = cve["publishedDate"]
                cve_id = cve["cve"]["CVE_data_meta"]["ID"]
            except:
                continue
            
            cve_info = {
                "cveid": cve_id,
                "pub_date": pub_date,
                "mod_date": mod_date,
                "summary": summary,
                "cvss_base": base,
                "cvss_impact": impact,
                "cvss_exploit": exploit,
                "cvss_access_vector": access_vector,
                "cvss_access_complexity": access_complexity,
                "cvss_authentication": authentication,
                "cvss_confidentiality_impact": confidentiality_impact,
                "cvss_integrity_impact": integrity_impact,
                "cvss_availability_impact": availability_impact,
                "cvss_vector": vector,
                "cweid": cweid
            }

            cve_list.append(cve_info)
        jsonfile.close()
    
    return cve_list
