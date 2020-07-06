from os import listdir
from os.path import isfile, join
from zipfile import ZipFile
import xml.etree.ElementTree as et
from datetime import datetime
import csv
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

                cve_id = cve.get("cve").get("CVE_data_meta").get("ID")
                last_mod_date = datetime.strptime(cve.get("lastModifiedDate"), "%Y-%m-%dT%H:%MZ")
                pub_date = datetime.strptime(cve.get("publishedDate"), "%Y-%m-%dT%H:%MZ")
                summary = cve.get("cve").get("description").get("description_data")[0].get("value")
                impact = cve.get("impact")

                if "REJECT" in summary:
                    continue

                if impact != {}:
                    baseMetricV2 = impact.get("baseMetricV2")

                    cvss_base = baseMetricV2.get("cvssV2").get("baseScore")
                    cvss_impact = baseMetricV2.get("impactScore")
                    cvss_exploit = baseMetricV2.get("exploitabilityScore")
                    cvss_access_vector = baseMetricV2.get("cvssV2").get("accessVector")
                    cvss_access_complexity = baseMetricV2.get("cvssV2").get("accessComplexity")
                    cvss_access_authentication = baseMetricV2.get("cvssV2").get("authentication")
                    cvss_confidentiality_impact = baseMetricV2.get("cvssV2").get("confidentialityImpact")
                    cvss_integrity_impact = baseMetricV2.get("cvssV2").get("integrityImpact")
                    cvss_availability_impact = baseMetricV2.get("cvssV2").get("availabilityImpact")
                    cvss_vector = baseMetricV2.get("cvssV2").get("vectorString")
                    cwe_id = cve.get("cve").get("problemtype").get("problemtype_data")[0].get("description")[0].get("value")
                else:

                    cvss_base = None
                    cvss_impact = None
                    cvss_exploit = None
                    cvss_access_vector = None
                    cvss_access_complexity = None
                    cvss_access_authentication = None
                    cvss_confidentiality_impact = None
                    cvss_integrity_impact = None
                    cvss_availability_impact = None
                    cvss_vector = None

            except AttributeError as e:
                print(e)
                print(cve_id)
                print(cve.get("impact"))
                print(summary)
                print("------------")
                continue

            cve_info = {
                "cve_id": cve_id,
                "published_date": pub_date,
                "last_modified_date": last_mod_date,
                "summary": summary,
                "cvss_base": cvss_base,
                "cvss_impact": cvss_impact,
                "cvss_exploit": cvss_exploit,
                "cvss_access_vector": cvss_access_vector,
                "cvss_access_complexity": cvss_access_complexity,
                "cvss_access_authentication": cvss_access_authentication,
                "cvss_confidentiality_impact": cvss_confidentiality_impact,
                "cvss_integrity_impact": cvss_integrity_impact,
                "cvss_availability_impact": cvss_availability_impact,
                "cvss_vector": cvss_vector,
                "cwe_id": cwe_id
            }
            cve_list.append(cve_info)
    jsonfile.close()
    
    return cve_list

# def make_csv():
#     csv_columns = ["cve_id", 
#                     "published_date",
#                     "last_modified_date",
#                     "summary",
#                     "cvss_base",
#                     "cvss_impact",
#                     "cvss_exploit",
#                     "cvss_access_vector",
#                     "cvss_access_complexity",
#                     "cvss_access_authentication",
#                     "cvss_confidentiality_impact",
#                     "cvss_integrity_impact",
#                     "cvss_availability_impact",
#                     "cvss_vector",
#                     "cwe_id"]
#     cves = unzipJson()
#     print('test')
#     try:
#         with open('cve.csv', 'w') as csvFile:
#             writer = csv.DictWriter(csvFile, fieldnames=csv_columns)
#             writer.writeheader()
#             for data in cves:
#                 writer.writerow(data)
#     except IOError:
#         print("I/O error")
