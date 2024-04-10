import requests
import json
import re
import pickle
import threading

url = "https://console-api.enforce.dev/query"
headers = {
   "chainguard-active-since": "2020-04-02T20:42:57.240Z"
}
data = {
   "operationName": "ImageCatalog",
   "query": "query ImageCatalog($privateCatalogOrg: ID!, $excludeDates: Boolean = true) {\n  repos(filter: {uidp: {descendantsOf: $privateCatalogOrg}}) {\n    id\n    name\n    friendlyName\n    keywords\n    readme\n    tags(\n      filter: {excludeDates: $excludeDates, excludeEpochs: true, excludeReferrers: true}\n    ) {\n      id\n      name\n      digest\n      lastUpdated\n      keywords\n      __typename\n    }\n    __typename\n  }\n}",
   "variables": {
       "privateCatalogOrg": "ce2d1984a010471142503340d670612d63ffb9f6"
   }
}

table = "| Image | Criticals | Highs | Mediums | Lows | Unknown | Negligble |\n| -- | -- | -- | -- | -- | -- | -- |\n"


response = requests.post(url, headers=headers, json=data)

images = []

def chunker(seq, size):
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))

def scan_and_output(images):
    images = images.split(',')
    for image in images:
        try:
            import pygrype
            GRYPE = pygrype.Grype()
            scan = GRYPE.scan(image)
            if scan.matches:
                with open('{}.pkl'.format(image.replace("/", "-")), 'wb') as file: 
                    pickle.dump(scan, file)
        except json.decoder.JSONDecodeError:
            print(f"Failed to scan {image}")

def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))


def get_images_and_scan():
    if response.status_code == 200:
        response_json = json.loads(response.text)
        matching_strings = re.findall(r"cgr\.dev\/[a-zA-Z\-0-9]+\/[a-zA-Z\-0-9]+:latest", response.text, flags=re.MULTILINE)

        # probably need to make matching_strings into a set?

        print(len(matching_strings))
        
        imageSplit = list(split(matching_strings, 25))
        print(imageSplit[0])

        print("Going to make {} thread. Proceed?".format(len(imageSplit)))
        for images in imageSplit:
            thread = threading.Thread(target=scan_and_output, args=(','.join(images),))
            thread.start()

    else:
        print("Request failed with status code:", response.status_code)
        print("Response text:", response.text)


def get_stats_from_pkls():
    global table

    import glob

    pattern = "results/*.pkl"

    statStr = """| Severity | Total |\n| -- | -- |\n| Critical | {critical} |\n| High | {high} |\n| Medium | {medium} |\n| Low | {low} |\n| Unknown | {unknown} |\n| Negligible | {negligible} |"""
    
    stats = {
        'crticial': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'unknown': 0,
        'negligible': 0,
    }
    
    pkl_files = glob.glob(pattern)

    for image in pkl_files:

        file = open(image, 'rb')

# dump information to that file
        data = pickle.load(file)

        # data.source.target.userInput
        # Criticals, Highs, Mediums, Lows, Unknown, Neglibble
        criticals = list(filter(lambda x: x.vulnerability.severity.lower() == 'critical', data.matches))
        highs = list(filter(lambda x: x.vulnerability.severity.lower() == 'high', data.matches))
        mediums = list(filter(lambda x: x.vulnerability.severity.lower() == 'medium', data.matches))
        lows = list(filter(lambda x: x.vulnerability.severity.lower() == 'low', data.matches))
        unknowns = list(filter(lambda x: x.vulnerability.severity.lower() == 'unknown', data.matches))
        negligibles = list(filter(lambda x: x.vulnerability.severity.lower() == 'negligible', data.matches))

        stats['crticial'] += len(criticals)
        stats['high'] += len(highs)
        stats['medium'] += len(mediums)
        stats['low'] += len(lows)
        stats['unknown'] += len(unknowns)
        stats['negligible'] += len(negligibles)


        ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in criticals])

        a = """| [{image}]({image}) | {critical} | {high} | {medium} | {low} | {unknown} | {negligible} |\n""".format(
            image = data.source.target.userInput,
            critical = ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in criticals]),
            high = ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in highs]),
            medium = ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in mediums]),
            low = ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in lows]),
            unknown = ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in unknowns]),
            negligible = ",".join(["[{}]({})".format(x.vulnerability.id, x.vulnerability.urls[0]) for x in negligibles]),
        )

        table += a

    stats = statStr.format(
        critical = stats["crticial"],
        high = stats["high"],
        medium = stats["medium"],
        low = stats["low"],
        unknown = stats["unknown"],
        negligible = stats["negligible"],
    )

    return table, stats

table, stats = get_stats_from_pkls()

print(stats)

print(table)