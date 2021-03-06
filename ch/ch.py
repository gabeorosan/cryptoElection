from flask import Flask, render_template, request
import os
from sqlalchemy import Column, String
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from InitForm import InitForm
from EncryptForm import EncryptForm
from DecryptForm import DecryptForm
import rsa
from ciphers import AESCipher 
import hashlib
import pyDHE
from ast import literal_eval

hash_len = 20 #length of SHA1 hash in bytes for assertions & int conversions

#initialize app
app = Flask(__name__)
app.secret_key = os.urandom(12).hex()

#set up database
engine = create_engine('sqlite:///ch/sqlite/ch.db', echo=False)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=True,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()
@app.teardown_appcontext
def teardown_db(error):
    db_session.close()
    engine.dispose()

class RSA(Base):
    #set up SQLite columns
    __tablename__ = 'rsa'
    __table_args__ = {'extend_existing': True} 
    n = Column(String, primary_key=True)
    e = Column(String)
    d = Column(String)
    p = Column(String)
    q = Column(String)
    exp1 = Column(String)
    exp2 = Column(String)
    
    def __init__(self):
        #initialize keys, 1024 bits
        (pubkey, privkey) = rsa.newkeys(1024)
        n, e, d, p, q, exp1, exp2, coef = privkey.__getstate__()
        self.n = str(n)
        self.e = str(e)
        self.d = str(d)
        self.p = str(p)
        self.q = str(q)
        self.exp1 = str(exp1)
        self.exp2 = str(exp2)

class DHKE(Base):
    #set up SQLite columns
    __tablename__ = 'dhke'
    __table_args__ = {'extend_existing': True} 
    
    group = Column(String)
    g = Column(String)
    p = Column(String)
    a = Column(String, primary_key=True)
    public = Column(String)
    key = Column(String)
    
    def __init__(self):
        #initialize keys, group 14 by default
        dh = pyDHE.new()
        group, g, p, a, public, key = dh.__dict__.values()
        self.group = str(group)
        self.g = str(g)
        self.p = str(p)
        self.a = str(a)
        self.public = str(public)
        self.key = str(key)

#return SHA1 hash of a string
def shash(x):
    assert type(x) == str
    sha = hashlib.sha1()
    sha.update(x.encode())
    return sha.digest()

#return MD5 hash of a string
def mash(x):
    assert type(x) == str
    m = hashlib.md5()
    m.update(x.encode())
    return m.digest()

#clear all instances of a given class from database
def clear_class(c):
    instances = c.query.all()
    for i in instances:
        db_session.delete(i)
    db_session.commit()

#renew DH keys
def dhke_renew():
    clear_class(DHKE)
    db_session.add(DHKE())
    db_session.commit()

#renew RSA keys
def rsa_renew():
    clear_class(RSA)
    db_session.add(RSA())
    db_session.commit()

#get shared key from another party's private key
#automatically renew public key & add it to database
def dhke_get_shared(A):
    assert type(A) == int
    dh = DHKE()
    shared = str(pow(int(A), int(dh.a), int(dh.p)))
    dh.key = shared
    old_dh = DHKE.query.one()
    db_session.delete(old_dh)
    db_session.add(dh)
    db_session.commit()
    return shared

#get an instance of AES from a given Diffie Hellman shared key
#the AES key is MD5 hash of shared key
def get_aes(shared):
    assert type(shared) == str 
    aes = AESCipher(mash(shared))
    return aes

#sign message (int) with RSA & encrypt with AES
def encrypt(x, aes):
    '''
    used for encrypting SSN/id and Validation Number
    Args:
        x: number to be encrypted
        aes: AES instance

    Returns: encrypted ciphertext (bytes)
    '''
    assert type(x) == str
    h = shash(x)
    intx = int.from_bytes(h, byteorder='big', signed=False)
    rsakeys = RSA.query.all()[0]
    msgs = {}
    msgs['x'] = x
    msgs['hash'] = h
    msgs['intx'] = intx
    msgs['rsa_enc'] = rsa.core.encrypt_int(intx, int(rsakeys.d), int(rsakeys.n))
    msgs['aes_enc'] = aes.encrypt(str(msgs['rsa_enc']))
    return msgs['aes_enc']

#decrypt a message that has been RSA signed and AES encrypted
def decrypt(y, aes, n, e):
    '''
    used to decrypt Validation number from CLA
    Args: 
        y: ciphertext (bytes) to be decrypted
        aes: AES instance
        n, e: RSA public exponent & modulus used in encryption

    Returns: decrypted int converted to bytes (b/c hashing is used before encryption)
    '''
    assert type(y) == bytes
    assert type(n) == int
    assert type(e) == int
    msgs = {}
    msgs['aes_enc'] = y
    msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
    msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), int(e), int(n))
    return msgs['rsa_dec']

#home page
@app.route("/", methods=['GET', 'POST'])
def home():
    iform = InitForm(request.form)
    eform = EncryptForm(request.form)
    dform = DecryptForm(request.form)

    #response from CH (encrypted ciphertext or decrypted plaintext)
    res = []

    if request.method=='POST':
        if iform.init.data and iform.validate():
            rsa_renew()
            dhke_renew()
        elif eform.encrypt.data and eform.validate():
            #sign & encrypt the given message w/ DH public exponent
            #respond with the encrypted plaintext
            msg = literal_eval(eform.msg.data)
            A = int(eform.A.data)
            shared = dhke_get_shared(A)
            aes = get_aes(shared)
            y = encrypt(str(msg), aes)
            res.append(y)
        elif dform.decrypt.data and dform.validate():
            #decrypt the given message w/ DH & RSA public info
            #respond with the decrypted plaintext
            msg = literal_eval(dform.msg.data)
            n = int(dform.rsapub_n.data)
            e = int(dform.rsapub_e.data)
            dh = DHKE.query.one()
            shared = int(dh.key)
            aes = get_aes(str(shared))
            x = decrypt(msg, aes, n, e)
            res.append(x)

    rsakeys = RSA.query.all()
    dhke = DHKE.query.all()
    return render_template('home.html', iform=iform, eform=eform, dform=dform, rsakeys=rsakeys, dhke=dhke, res=res)

if __name__ == '__main__':
    with app.app_context():
        Base.metadata.create_all(bind=engine)       
        app.run(host="localhost", port=5000,debug=False)
