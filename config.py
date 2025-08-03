# config.py

# class Config:
#     SECRET_KEY = 'a1b785d1cab036c569bd88b97968a69b3ff9f650ddc38dbbb60729548cbe555b'  # change this
#     LDAP_SERVER = 'ldap://server01.vvs.com'
#     DOMAIN = 'VVS'  # e.g., MYCOMPANY

class Config:
    SECRET_KEY = 'a1b785d1cab036c569bd88b97968a69b3ff9f650ddc38dbbb60729548cbe555b'
    LDAP_SERVER = '192.168.10.80'  # ✅ REMOVE 'ldap://' prefix — just the IP or hostname
    DOMAIN = 'vvs.com'             # ✅ Use lowercase domain name (same as realm output)
    
    # # ✅ Add these lines below
    BASE_DN = 'DC=vvs,DC=com'
    # USER_OU = 'OU=LinuxUsers'
    # GROUP_OU = 'OU=LinuxGroups'