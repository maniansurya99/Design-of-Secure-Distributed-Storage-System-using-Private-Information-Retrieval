from flask import Flask, request, render_template, jsonify
import pypyodbc
import textwrap
import math

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

app = Flask(__name__)
 
emailid = ""
noofdb = 0


encpwd = "8UBss43$%&6"
secretkey = "wisen"

def encrypt(raw):
    private_key = hashlib.sha256(encpwd.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode('ascii', 'ignore')))


def decrypt(enc):
    private_key = hashlib.sha256(encpwd.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


@app.route("/")
def home():
    return render_template('Login.html', processResult="")

@app.route('/processLogin', methods=['GET'])
def processLogin():
    global emailid
    emailid= request.args.get('emailid')
    password= request.args.get('password')
    conn1 = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;Database=PrivateInformationRetrievalV1', autocommit=True)
    cur1 = conn1.cursor()
    sqlcmd1 = "SELECT * FROM UserTable WHERE emailid = '"+emailid+"' AND password = '"+password+"' AND isActive = 1"; 
    print(sqlcmd1)
   
    cur1.execute(sqlcmd1)
    row = cur1.fetchone()
    cur1.commit()
    if not row:
        return render_template('Login.html', processResult="Invalid Credentials")
    return render_template('Dashboard.html')


@app.route('/ChangePassword')
def changePassword():
    
    
    oldPassword= request.args.get('oldPassword')
    newPassword= request.args.get('newPassword')
    conn1 = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;Database=PrivateInformationRetrievalV1', autocommit=True)
    cur1 = conn1.cursor()
    sqlcmd1 = "SELECT * FROM UserTable WHERE emailid = '"+emailid+"' AND password = '"+oldPassword+"'"; 
    cur1.execute(sqlcmd1)
    row = cur1.fetchone()
    cur1.commit()
    if not row:
        data = {'type': 'error', 'message': 'Invalid Old Password'}
        return jsonify(data)

    
    conn2 = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;Database=PrivateInformationRetrievalV1', autocommit=True)
    cur2 = conn2.cursor()
    sqlcmd2 = "UPDATE UserTable SET password = '"+newPassword+"' WHERE emailid = '"+emailid+"'"; 
    print(sqlcmd2)
    cur1.execute(sqlcmd2)
    cur2.commit()
    data = {'type': 'success', 'message': 'Password Changed Successfully'}
    return jsonify(data)



@app.route("/Dashboard")
def Dashboard():
    return render_template('Dashboard.html')

@app.route("/CreateDatabase")
def CreateDatabase():
    return render_template('CreateDatabase.html', processResult="")

@app.route("/ProcessCreateDatabase",methods = ['POST'])
def ProcessCreateDatabase():
    global noofdb
    temp = request.form['dbcnt']
    dbcnt = int(temp)
    noofdb = dbcnt
    print(type(dbcnt))
    if type(dbcnt) != int :
        return render_template('CreateDatabase.html', processResult='No of Databases must be Integer')
    
    
    if dbcnt > 10 :
        return render_template('CreateDatabase.html', processResult='No of Databases must be less than 10')
    
    
    
    for index in range(dbcnt): 
        connection = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;', autocommit=True)  
  
        cursor = connection.cursor()   
        sqlcmd = "CREATE DATABASE db" + str(index+1)
        cursor.execute(sqlcmd)
        cursor.commit() 
        connection.close()  
    
    for index in range(dbcnt): 
        conn1 = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;Database=db'+ str(index+1), autocommit=True)
        cur1 = conn1.cursor() 
        if not cur1.tables(table='MyTable', tableType='TABLE').fetchone():
            sqlcmd1 = "CREATE Table MyTable (SecretData nvarchar(MAX))" 
            cur1.execute(sqlcmd1)
            cur1.commit()
            cur1.close()
            conn1.close()
        
    
    return render_template('InsertData.html', processResult="Done. Databases Created. ")


@app.route("/InsertData")
def InsertData():
    return render_template('InsertData.html', processResult="")

import pyAesCrypt
import io
import base64
sdata = ""
@app.route("/ProcessInsertData",methods = ['POST'])
def ProcessInsertData():
    global noofdb, secretkey, sdata
    noofdb=2
    sdata = request.form['sdata']

    if len(sdata.strip()) < noofdb :
        return render_template('CreateDatabase.html', processResult='Invalid Input Data')
    
    
    connection = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;', autocommit=True)  
  
    cursor = connection.cursor()   
    
    
    domain = sdata
    data = textwrap.wrap(domain, math.ceil(len(domain) / noofdb))
    for index in range(noofdb): 
        conn1 = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;Database=db'+ str(index+1), autocommit=True)
        cur1 = conn1.cursor() 
        if cur1.tables(table='MyTable', tableType='TABLE').fetchone():
            bufferSize = 64 * 1024
            password = "wisen"

            # binary data to be encrypted
            pbdata = b"data[index] \x00\x01"

            # input plaintext binary stream
            fIn = io.BytesIO(pbdata)

            # initialize ciphertext binary stream
            fCiph = io.BytesIO()

            # initialize decrypted binary stream
            fDec = io.BytesIO()

            # encrypt stream
            pyAesCrypt.encryptStream(fIn, fCiph, password, bufferSize)

            print(str(fCiph.getvalue()))
            sdata = str(fCiph.getvalue()).replace("'", "''")
            sqlcmd1 = "INSERT INTO MyTable (SecretData) VALUES('"+sdata+"')"
            print(sqlcmd1)
            cur1.execute(sqlcmd1)
            cur1.commit() 
            pass
        conn1.close()
        
    connection.close()  
        
    
    return render_template('InsertData.html', processResult="Done. Data are Stored. ")

@app.route('/GetData')
def getData():
    return render_template('GetData.html', processResult="")

@app.route('/GetData',methods = ['POST'])
def getDataPost():
    global noofdb, sdata

    noofdb = 2
    connection = pypyodbc.connect('Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;',
                                  autocommit=True)
    cursor = connection.cursor()
    mydata = []
    for index in range(noofdb):
        conn1 = pypyodbc.connect(
            'Driver={SQL Server};Server=WISEN\\SQLEXPRESS;Integrated_Security=true;Database=db' + str(index + 1),
            autocommit=True)
        cur1 = conn1.cursor()
        sqlcmd1 = "SELECT * FROM MyTable"
        cur1.execute(sqlcmd1)
        dbrow = cur1.fetchone()
        cur1.commit()
        if dbrow:
            data = dbrow[0]


            # print decrypted data

            print(data)
            mydata.append(data)
            cur1.commit()
        conn1.close()

    connection.close()
    print(mydata)
    dedata = ''.join(mydata)
    bufferSize = 64 * 1024
    password = "wisen"

    # binary data to be encrypted

    # input plaintext binary stream

    # initialize ciphertext binary stream
    fCiph = io.BytesIO()

    # initialize decrypted binary stream
    fDec = io.BytesIO()

    ctlen = len(dedata)
    fCiph.seek(0)

    try:
        sdata = pyAesCrypt.decryptStream(fCiph, fDec, password, bufferSize, ctlen)
    except:
        pass
    print(sdata)
    return render_template('GetData.html', processResult=sdata)
if __name__ == "__main__":
    app.run()
