from flask import Flask, render_template, request, flash, redirect
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import requests

app = Flask(__name__,instance_relative_config=True)

app.config.from_pyfile('config.py', silent=True)

csrf = CSRFProtect()
csrf.init_app(app)



@app.route('/verifybvn')
def home():
    return render_template('bvntest.html')

@app.route('/raveform')
def raveform():
    if request.args.get('response'):
            alert_ = 'Transaction Successful'
            flash(alert_, category='success')
            return redirect('/raveform')
    else:
        return render_template('index.html')

@app.route('/bvn_verify', methods=['POST','GET'])
def bvn_verify():
    
    bvn = request.form['bvn']
    first_name = request.form['firstname']
    last_name = request.form['lastname']
    dob = request.form['dob']

    import requests

    headers = {
        'content-type': 'application/json',
    }

    params = (
        ('seckey', 'FLWSECK-e6db11d1f8a6208de8cb2f94e293450e-X'),
    )

    #response = requests.get('https://ravesandboxapi.flutterwave.com/v2/kyc/bvn/12345678901', headers=headers, params=params)

    #NB. Original query string below. It seems impossible to parse and
    #reproduce query strings 100% accurately so the one below is given
    #in case the reproduced version is not "correct".
    response = requests.get('https://ravesandboxapi.flutterwave.com/v2/kyc/bvn/'+bvn+'?seckey=FLWSECK-e6db11d1f8a6208de8cb2f94e293450e-X', headers=headers)



    if response:
        dictresponse = response.json()
        status = dictresponse['status']
        data = dictresponse['data']

        
        if status == 'success':
            if data['bvn'] == bvn and data['date_of_birth'] == dob:
                alert_ =  'BVN Verification Successful'
                flash(alert_, category='success')
            else:
                error = 'BVN does not match date of birth provided'
                flash(error, category='error')
        else:
            error =  'BVN does not exist'
            flash(error, category='error') 
    else:
        error = 'An error Occurred'
        flash(error, category='error')
    return redirect('/')

@app.route('/paytorave', methods=['POST','GET'])
def paytorave():
    
    cardno = request.form['cardno']
    cvv = request.form['cvv']
    pin = request.form['pin']
    expm = request.form['cardexpmonth']
    expy = request.form['cardexpyear']
    amount = request.form['amount']
    firstname = request.form['firstname']
    email = request.form['email']

    import os, hashlib, warnings, requests, json
    import base64
    from Crypto.Cipher import DES3

    class PayTest(object):

        """this is the getKey function that generates an encryption Key for you by passing your Secret Key as a parameter."""

        def __init__(self):
            pass

        def getKey(self,secret_key):
            hashedseckey = hashlib.md5(secret_key.encode("utf-8")).hexdigest()
            hashedseckeylast12 = hashedseckey[-12:]
            seckeyadjusted = secret_key.replace('FLWSECK-', '')
            seckeyadjustedfirst12 = seckeyadjusted[:12]
            return seckeyadjustedfirst12 + hashedseckeylast12

        """This is the encryption function that encrypts your payload by passing the text and your encryption Key."""

        def encryptData(self, key, plainText):
            blockSize = 8
            padDiff = blockSize - (len(plainText) % blockSize)
            cipher = DES3.new(key, DES3.MODE_ECB)
            plainText = "{}{}".format(plainText, "".join(chr(padDiff) * padDiff))
            # cipher.encrypt - the C function that powers this doesn't accept plain string, rather it accepts byte strings, hence the need for the conversion below
            test = plainText.encode('utf-8')
            encrypted = base64.b64encode(cipher.encrypt(test)).decode("utf-8")
            return encrypted


        def pay_via_card(self):
            data = {
            "PBFPubKey": "FLWPUBK-41ff7286b6aba0b4355f7e20bd998313-X",
            "cardno": cardno,
            "cvv": cvv,
            "expirymonth": str(expm),
            "expiryyear": str(expy),
            "currency": "NGN",
            "pin": pin,
            "country": "NG",
            "amount": str(amount),
            "email": email,
            "suggested_auth": "PIN",
            "phonenumber": "0902620185",
            "firstname": firstname,
            "lastname": "desola",
            "subaccounts": [
                {
                "id": "RS_7D65C49AEEE15BD7FEF82D42C9F46B59"
                },
                
            ],
            # "meta": [
            #     {
            #     "metaname": "flightID",
            #     "metavalue": "123949494DC"
            #     }
            # ],
            "IP": "355426087298442",
            "txRef": "MC-" + str(datetime.now()), # your unique merchant reference
            "redirect_url": "http://localhost:5000/raveform",
            # "device_fingerprint": "69e6b7f0b72037aa8428b70fbe03986c"
            }

            sec_key = 'FLWSECK-24b8ce267689e5e535af78d1ff71f21b-X'

            # hash the secret key with the get hashed key function
            hashed_sec_key = self.getKey(sec_key)

            # encrypt the hashed secret key and payment parameters with the encrypt function

            encrypt_3DES_key = self.encryptData(hashed_sec_key, json.dumps(data))

            # payment payload
            payload = {
                "PBFPubKey": "FLWPUBK-41ff7286b6aba0b4355f7e20bd998313-X",
                "client": encrypt_3DES_key,
                "alg": "3DES-24"
            }

            # card charge endpoint
            endpoint = "https://ravesandboxapi.flutterwave.com/flwv3-pug/getpaidx/api/charge"

            # set the content type to application/json
            headers = {
                'content-type': 'application/json',
            }

            response = requests.post(endpoint, headers=headers, data=json.dumps(payload))
            dictdata = response.json()
            return dictdata

            
    rave = PayTest()
    data_ = rave.pay_via_card()
    #return str(data_)
    if data_['status'] == 'error':
        alert_ = 'An error occurred, please try again'
        flash(alert, category='error')
        return redirect ('/raveform')
    else:

        tr_ref = data_['data']['flwRef']

        if data_['data']['authModelUsed'] == 'PIN':

            headers = {
                'content-type': 'application/json',
            }

            data = '{"PBFPubKey":"FLWPUBK-41ff7286b6aba0b4355f7e20bd998313-X","transaction_reference":'+tr_ref+',"otp":12345}'

            respons = requests.post('https://api.ravepay.co/flwv3-pug/getpaidx/api/validatecharge', headers=headers, data=data)
            resp = respons.json()
            return str(resp)
        elif data_['data']['authModelUsed'] == 'VBVSECURECODE':
            
            return redirect(data_['data']['authurl'])


@app.route('/validate')
def validate():
    header = {
        'content-type': 'application/json',
    }

    data = '{"PBFPubKey":"FLWPUBK-7adb6177bd71dd43c2efa3f1229e3b7f-X","transaction_reference":"FLW-MOCK-ce3654ac725278c4e2b7700c3af1fab8","otp":12345}'

    
    response = requests.post('https://api.ravepay.co/flwv3-pug/getpaidx/api/validatecharge', headerd=header, data=data)
    resp = response.json
    return str(resp)
    #return render_template('index.html')

if __name__=='__main__':
    app.run(debug=True)