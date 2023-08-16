from enum import Enum

class FileType(Enum):
    CPE = 1

    CVE = 2

    CWE_REFERENCE = 4
    CWE_WEAKNESS = 5
    CWE_CATEGORY = 6
    CWE_VIEW = 7

    CAPEC_REFERENCE = 8
    CAPEC_ATTACK = 9
    CAPEC_CATEGORY = 10
    CAPEC_VIEW = 11