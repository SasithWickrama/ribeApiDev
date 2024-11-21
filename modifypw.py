import os
import subprocess
from datetime import datetime
from log import Logger
import hashlib
import base64

def hash_generate(password_text):
    salt = os.urandom(8)
    hashed_password = hashlib.sha1(password_text.encode('utf-8') + salt).digest()
    final_hash = base64.b64encode(hashed_password + salt).decode('utf-8')
    return "{SSHA}" + final_hash

cdate = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

loggermod = Logger('modifypw', 'logs/modifypw')

class modifypassword:
    def Modifypw(self, ref, password_text):
        repdesc = 'modify password from OSS on ' + str(cdate) + "-" + ref
        loggermod.info(ref + " - " + str(repdesc))
        ldap_hash = hash_generate(password_text)
        
        ldapip = "10.68.74.32"
        ldappwd = "o$Sld@PAdm!N"
        ldapusr = "OSSUser"
        
        if self != "":
            with open('files/modifypw.ldif', 'r') as xmlfile:
                body = xmlfile.read()

            indata = {"uidrep": self, "repdesc": repdesc, "bbPasswd" : ldap_hash}
            for key in indata:
                value = indata[key]
                body = body.replace(key, value)

            filename = self + '.ldif'
            with open(filename, 'w') as fh:
                fh.write(body)

            loggermod.info(ref + " - " + str(body))
            loggermod.info(ref + " - " + str(ldapip)+ " - " + str(ldapusr)+ " - " + str(ldappwd))
            
            # Directly execute ldapmodify without using cmd
            #cmd = ['ldapmodify', '-h', ldapip, '-D', f'uid={ldapusr},cn=config', '-w', ldappwd, '-f', filename]
            cmd = ['/usr/bin/ldapmodify', '-h', ldapip, '-D', f'uid={ldapusr},cn=config', '-w', ldappwd, '-f', filename]
            cmdexe = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            result_stdout, result_stderr = cmdexe.communicate()

            loggermod.info(ref + " - STDOUT: " + str(result_stdout))
            loggermod.info(ref + " - STDERR: " + str(result_stderr))

            if cmdexe.returncode != 0:
                responsedata = {"result": "failed", "msg": f'LDAP modify password failed with return code {cmdexe.returncode}'}
            else:
                responsedata = {"result": "success", "msg": 'LDAP modify password Completed'}

            os.remove(filename)
            return responsedata
        else:
            responsedata = {"result": "failed", "msg": 'invalid request check the parameters'}
            return responsedata
