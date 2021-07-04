"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""

from stix2 import Filter
import requests
from stix2 import MemoryStore

tactics = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
           'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
           'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact']


def get_data_from_branch(domain, branch="master"):
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])


src = get_data_from_branch("enterprise-attack")


def get_technique_by_name(name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    technique = src.query(filt)
    for val in technique:
        t = val['external_references']
        if 'external_id' in t[0]:
            return t[0]['external_id']
        else:
            return 0


def get_technique_by_id(id):
    filt = [
        Filter("external_references.external_id", "=", id),
        Filter("type", "=", "attack-pattern")]
    technique = src.query(filt)[0]
    return technique['name']


def get_tactic_techniques(tactic):
    res = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])

    tactics = {}
    for val in res:
        name = val['name']
        id = val['external_references'][0]
        rid = id['external_id']
        if "." not in rid:
            tactics[name] = rid

    return tactics
