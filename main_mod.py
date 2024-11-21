import random
import requests
import json
from log import Logger
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import base64
import db
from modifypw import modifypassword

app = Flask(__name__)
api = Api(app)

loggerbb = Logger('ribeACSbb', 'logs/ribeACSbb')
loggervoice = Logger('ribeACSvoice', 'logs/ribeACSvoice')
loggervdel = Logger('ribeACSdel', 'logs/ribeACSdel')
loggerBBpw = Logger('ribeBBpw', 'logs/ribeBBpw')

def random_ref(length):
    sample_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    return ''.join((random.choice(sample_string)) for x in range(length))


class acsBBProvision(Resource):
    def post(self):
        ref = random_ref(15)
        try:
            data = request.get_json()
            loggerbb.info(ref + " Received JSON data:" + str(data))  

            serial_number = data.get("serialNumber", "")
            phone_number = data.get("bbUserName", "")
            password = data.get("bbPassword", "")
            modifypassword.Modifypw(phone_number, ref, password)
            #password = random_ref(8)
            #newusercreate.newuser(data, ref, password)
            #loggerbb.info(ref + " BBPasswd :" + str(password))
  
            loggerbb.info(ref + " data :" + str(data))
            
            url = f"http://acs.slt.com.lk:8086/api/ump/v3/propertyServices/serial/{serial_number}"

            loggerbb.info(ref + " url :" + str(url))
            payload = json.dumps({
                "multiShot": True,
                "domain": "/",
                "enabled": True,
                "add": {
                    "PPPUNOSS": str(phone_number)+'@sltbbv6',
                    "PPPPasswordOSS": password
                }
            })
            loggerbb.info(ref + " payload :" + str(payload))
            headers = {
                'Authorization': 'Basic cmVzdEludGVncmF0aW9uOkFUSmlOVXZob28=',
                'Content-Type': 'application/json'
            }

            response = requests.patch(url, headers=headers, data=payload)
            loggerbb.info(ref + " response :" + str(response))
            
            response_data = json.loads(response.text)

            return response_data
            
        except Exception as e:
            loggerbb.info(ref + " exception :" + str(e))
            return {"error": str(e)}
            
class acsVoiceProvision(Resource):
    def post(self):
        ref = random_ref(15)
        try:
            data = request.get_json()

            serial_number = data.get("serialNumber", "")
            bbUserName = data.get("bbUserName", "")  
            password = data.get("voicePassword", "")
            
            loggervoice.info(ref + " data :" + str(data))
            
            VOIPDirectoryNumber = "+" + bbUserName
            voipUNnew = "+" + bbUserName + "F0" + "@sltims.lk"
            
            url = f"http://acs.slt.com.lk:8086/api/ump/v3/propertyServices/serial/{serial_number}"

            loggervoice.info(ref + " url :" + str(url))
            payload = json.dumps({
                "multiShot": True,
                "domain": "/",
                "enabled": True,
                "properties": {
                    "VOIPUNOSS": voipUNnew,
                    "VOIPPasswordOSS": password,
                    "VOIPDirectoryNumber": VOIPDirectoryNumber,
                }
            })
            loggervoice.info(ref + " payload :" + str(payload))
            headers = {
                'Authorization': 'Basic cmVzdEludGVncmF0aW9uOkFUSmlOVXZob28=',
                'Content-Type': 'application/json'
            }

            response = requests.put(url, headers=headers, data=payload)
            loggervoice.info(ref + " response :" + str(response))
            
            response_data = json.loads(response.text)

            return response_data
            
        except Exception as e:
            loggervoice.info(ref + " exception :" + str(e))
            return {"error": str(e)}

class ACS_API:
    def __init__(self):
        self.base_url = "http://acs.slt.com.lk:8086/api/ump/v3/"
        self.username = "restIntegration"
        self.password = "ATJiNUvhoo"
        self.auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()

    def get_device_id(self, serial_number):
        try:
            url = f"{self.base_url}devices?searchCriteria=serialNumber%20eq%20%27{serial_number}%27"
            headers = {"Authorization": f"Basic {self.auth}"}
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            data = response.json()
            if data:
                return data[0] 
            else:
                return None
        except Exception as e:
            print(f"Error in get_device_id: {e}")
            return None

    def delete_api(self, serial_number):
        try:
            url = f"{self.base_url}propertyServices/serial/{serial_number}"
            loggervdel.error(f"url: {url}")
            headers = {
                "Authorization": f"Basic {self.auth}",
                "Content-Type": "application/json"
            }
            # No payload needed for DELETE request, but passing an empty JSON object
            response = requests.delete(url, headers=headers, json={})
            response.raise_for_status()
            
            return response.status_code
        except requests.HTTPError as e:
            loggervdel.error(f"An error occurred in delete_api: {e.response.status_code} {e.response.reason}")
            raise e
        except Exception as e:
            loggervdel.error(f"An unexpected error occurred in delete_api: {e}")
            raise e


    def delete_cpe(self, device_id):
        try:
            url = f"{self.base_url}devices/{device_id}"
            loggervdel.error(f"url : "+url)
            headers = {
                "Authorization": f"Basic {self.auth}",
                "Content-Type": "application/json"
            }
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            
            return response.status_code
        except Exception as e:
            loggervdel.error(f"An error occurred in delete_cpe: {e}")
            raise e

    def factory_reset(self, device_id):
        try:
            url = f"{self.base_url}tasksFromTemplates/device/{device_id}"
            loggervdel.error(f"url : "+url)
            headers = {
                "Authorization": f"Basic {self.auth}",
                "Content-Type": "application/json"
            }
            payload = {"templateName": "FactoryResetTask"}
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()

            return response.status_code
        except Exception as e:
            loggervdel.error(f"Error in factory_reset: {e}")
            raise e

class ACSDeleteONT(Resource):
    def __init__(self):
        self.ref = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=15))
        super(ACSDeleteONT, self).__init__()

    def post(self):
        try:
            data = request.get_json()

            serial_number = data.get("serialNumber", "")
            bbUserName = data.get("bbUserName", "")  

            acs_api = ACS_API()

            device_id = acs_api.get_device_id(serial_number)
            loggervdel.info(self.ref + " device_id :" + str(device_id))
            
            if device_id:        
                result_delete_api = acs_api.delete_api(serial_number)
                loggervdel.info(self.ref + " delete_api :" + str(result_delete_api))
                
                result_delete_cpe = acs_api.delete_cpe(device_id)
                loggervdel.info(self.ref + " delete_cpe :" + str(result_delete_cpe))
                
                if result_delete_api == 200 and result_delete_cpe == 200:
                    loggervdel.info(self.ref + " Delete result : Success")
                    return {"status": "success", "response": "Device deleted successfully"}
                else:
                    loggervdel.error(self.ref + " Delete result : Failed")
                    return {"status": "error", "response": "Failed to delete device"}
            else:
                loggervdel.error(self.ref + " Device not found")
                return {"status": "error", "response": "Device not found"}
        except Exception as e:
            loggervdel.error(self.ref + " Exception occurred: " + str(e))
            return {"error": str(e)}

class getbbPassword:
    
    def getdetails(self, ref, data):
        try:
            bbUserName = data.get('bbUserName')
            refId = data.get('refId')

            db_connection = db.DbConnection()
            connection = db_connection.dbconnClarityadmin()
            
            if connection['status'] != "error":
                loggerBBpw.info(f"DB Connection: {str(ref)} - {str(connection)}")   
                cursor = connection['status'].cursor()

                # Execute the select query to get the record with minimum SEQUENCE_NO
                cursor.execute("""
                    SELECT LDAP_SERIAL_NUMBER, SEQUENCE_NO, LDAP_PLAIN_TEXT
                    FROM LDAP_HASH_PASSWORD_LOG
                    WHERE LDAP_STATUS = 'AVAILBLE'
                    AND SEQUENCE_NO = (SELECT MIN(SEQUENCE_NO) FROM LDAP_HASH_PASSWORD_LOG WHERE LDAP_STATUS = 'AVAILBLE')
                """)
                result = cursor.fetchone()
                loggerBBpw.info(f"getPassword Result: {str(ref)} - {str(result)}")
                
                if result:
                    ldap_serial_number, sequence_no, ldap_plain_text = result
                    response = {
                        "LDAP_SERIAL_NUMBER": ldap_serial_number,
                        "SEQUENCE_NO": sequence_no,
                        "LDAP_PLAIN_TEXT": ldap_plain_text
                    }
                    # Update LDAP_HASH_PASSWORD_LOG to set LDAP_STATUS to 'RESERVED' and LDAP_SO_NUMBER to :bbUserName
                    cursor.execute("""
                        UPDATE CLARITY_ADMIN.LDAP_HASH_PASSWORD_LOG
                        SET LDAP_STATUS = 'RESERVED',
                            LDAP_SO_NUMBER = :bbUserName
                        WHERE LDAP_SERIAL_NUMBER = :ldap_serial_number
                    """, ldap_serial_number=ldap_serial_number, bbUserName=bbUserName)
                    connection['status'].commit()

                    cursor.close()
                    connection['status'].close()
                    
                    loggerBBpw.info(f"response ldap_plain_text: {str(ref)} - {str(ldap_plain_text)}")
                    return {"status": "success", "response": ldap_plain_text}
                else:
                    loggerBBpw.info(f"error: {str(ref)} - No LDAP_PLAIN_TEXT available for the provided bbUserName and refId")
                    return {"status": "error", "response":"No LDAP_PLAIN_TEXT available for the provided bbUserName and refId"}
            else:
                loggerBBpw.info(f"error: {str(ref)} - Failed to establish database connection")                
                return {"status": "error", "response":"Failed to establish database connection"}

        except Exception as e:
            loggerBBpw.error(f"Exception in getdetails: {e}")
            return {"status": "error", "response": str(ref) + " - " + str(e)}


#get LDAP BB password from table
class getbbPasswd(Resource):
    def post(self):
        ref = random_ref(15)
        data = request.get_json()
        loggerBBpw.info("Request Json File: %s" % data)
        return getbbPassword.getdetails(self,ref,data)
        
#Create Service ACS            
api.add_resource(acsBBProvision, '/api/slt/v1/acsbbprov')
api.add_resource(acsVoiceProvision, '/api/slt/v1/acsvoiceprov')

#Delete Service ACS
api.add_resource(ACSDeleteONT, '/api/slt/v1/acsdelete')

#get LDAP BB password from table
api.add_resource(getbbPasswd, '/api/slt/v1/getbbPasswd')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=33475)