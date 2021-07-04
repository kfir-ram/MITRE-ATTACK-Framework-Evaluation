"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""


# merges two hash maps into one.
def merge_hash_maps(main_hash_map, external_hash_map):
    for key in external_hash_map.keys():
        if key in main_hash_map.keys():
            main_hash_map[key] = list(main_hash_map[key])
            for value in external_hash_map[key]:
                main_hash_map[key].append(value)
        else:
            main_hash_map[key] = external_hash_map[key]
    for key in main_hash_map.keys():
        main_hash_map[key] = set(main_hash_map[key])
    return main_hash_map
