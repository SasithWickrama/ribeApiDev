import os
import subprocess
from datetime import datetime
from log import Logger
#from dotenv import load_dotenv
import hashlib
import base64

def hash_generate(password_text):
    salt = os.urandom(8)
    hashed_password = hashlib.sha1(password_text.encode('utf-8') + salt).digest()
    final_hash = base64.b64encode(hashed_password + salt).decode('utf-8')
    return "{SSHA}" + final_hash

cdate = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

loggerresume = Logger('newuser', 'logs/newuserldap')

class newusercreate:
    def newuser(self, ref, bbpasswd):
        repdesc = 'new LDAP User create from RIBE on ' + cdate
        
        password_text = bbpasswd
        ldap_hash = hash_generate(password_text)

        if self['circuit'] != "":
            with open('files/newuser.ldif', 'r') as xmlfile:
                body = xmlfile.read()

            indata = {"uidrep": self['circuit'], "repdesc": repdesc, "bbPasswd" : ldap_hash}
            for key in indata:
                value = indata[key]
                body = body.replace(key, value)

            filename = self['circuit'] + '.ldif'
            with open(filename, 'w') as fh:
                fh.write(body)

            loggerresume.info(ref + " - " + str(body))

            cmd = 'cmd /c "ldapmodify -h {ldapip} -D \"uid={ldapusr},cn=config\" -w \"{ldappwd}\" -f {filename}"'.format(
                ldapip=os.getenv("ldapip", ""),
                ldapusr=os.getenv("ldapusr", ""),
                ldappwd=os.getenv("ldappwd", ""),
                filename=filename
            )

            cmdexe = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            result_stdout, result_stderr = cmdexe.communicate()

            loggerresume.info(ref + " - STDOUT: " + str(result_stdout))
            loggerresume.info(ref + " - STDERR: " + str(result_stderr))

            if cmdexe.returncode != 0:
                responsedata = {"result": "failed", "msg": f'LDAP modify password failed with return code {cmdexe.returncode}'}
            else:
                responsedata = {"result": "success", "msg": 'LDAP modify password Completed'}

            os.remove(filename)
            return responsedata
        else:
            responsedata = {"result": "failed", "msg": 'invalid request check the parameters'}
            return responsedata
