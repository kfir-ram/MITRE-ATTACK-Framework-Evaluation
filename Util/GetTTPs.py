"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""


# gets the TTPs on the main hash map based on the event ids of the user.
def get_ttp_from_event_ids(main_hash_map, event_ids):
    TTPs = []
    if type(event_ids) == int:
        event_ids = [event_ids]
    for eventId in event_ids:
        if eventId in main_hash_map.keys():
            for value in main_hash_map[eventId]:
                TTPs.append(value)
    TTPs = set(TTPs)
    return TTPs
