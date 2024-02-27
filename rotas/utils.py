import re


# TODO: this should be in a different place
def extract_company(email: str):
    res = re.findall(r"\@(.*?)\.", email)

    if res:
        return res[0]
