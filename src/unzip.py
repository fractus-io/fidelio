from os import listdir
from os.path import isfile, join
from zipfile import ZipFile
from lxml import etree
from datetime import datetime
import csv
import json
import pprint

def getList(dict): 
    return dict.keys() 

def check_empty(val):
    return None if val == "*" else val


def check_len(val):
    return [None, val] if len(val.split(" ")) > 1 else [val, None]

# unzips CVEs and returns a list with information
def parse_json():
    
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


def parse_xml():
    file = ZipFile('cpe/official-cpe-dictionary_v2.3.xml.zip')
    root = etree.parse(file.open(file.namelist()[0])).getroot()

    cpe_items = []

    vendors = set()

    products = set()

    for cpe_item in root[1:]:
        references = []
        for child in cpe_item.getchildren():
            if etree.QName(child).localname == "title":
                title = child.text

            if etree.QName(child).localname == "cpe23-item":
                name = child.get("name").split(":")

                part = check_empty(name[2].replace("/", ""))
                vendor = check_empty(name[3].replace("\\", ""))
                product = check_empty(name[4].replace("\\", ""))
                version = check_empty(name[5])
                update_version = check_empty(name[6])
                edition = check_empty(name[7])
                lang = check_empty(name[8])
                sw_edition = check_empty(name[9])
                target_sw = check_empty(name[10])
                target_hw = check_empty(name[11])
                other = check_empty(name[12])

            if etree.QName(child).localname == "references":
                refs = child.getchildren()
                for reference in refs:
                    url = reference.attrib.get("href")
                    ref_type, description = check_len(reference.text)

                    ref_data = {"url": url, "desc": description, "type": ref_type}
                    references.append(ref_data)

        cpe_data = {
            "title": title,
            "part": part,
            "version": version,
            "update_version": update_version,
            "version": version,
            "update_version": update_version,
            "edition": edition,
            "lang": lang,
            "sw_edition": sw_edition,
            "target_sw": target_sw,
            "target_hw": target_hw,
            "other": other,
            "references": references,
            "vendor": {
                "name": vendor,
            },
            "product": {
                "name": product
            },
        }

        cpe_items.append(cpe_data)
        vendors.add(vendor)
        products.add(product)

    return {
        "cpes": cpe_items,
        "vendors": list(vendors),
        "products": list(products),
    }
# This will later be replaced with db comunication
def make_cpe_csv():
    cpe_object = parse_xml()
    
    cpes = cpe_object['cpes']
    
    try:
        with open('csv/cpe.csv', 'w') as cpeFile:
            writer = csv.DictWriter(cpeFile, fieldnames=getList(cpes))
            writer.writeheader()
            for data in cpes:
                writer.writerow(data)
    except IOError:
        print("I/O error")
        
    # vendors = cpe_object['vendors']
    # products = cpe_object['products']

# This will later be replaced with db comunication
def make_cve_csv():
    cves = parse_json()
    
    try:
        with open('csv/cve.csv', 'w') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=getList(cves))
            writer.writeheader()
            for data in cves:
                writer.writerow(data)
    except IOError:
        print("I/O error")
