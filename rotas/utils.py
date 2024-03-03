import re


def get_allowed_origins():
    import os
    origins = os.environ.get('ALLOWED_ORIGINS', [])

    if isinstance(origins, str):
        return origins.split(',')

    return origins


# TODO: this should be in a different place
def extract_company(email: str):
    res = re.findall(r"\@(.*?)\.", email)

    if res:
        return res[0]
