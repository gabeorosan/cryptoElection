from flask import Flask, render_template, request, jsonify
import os
import rsa
from sqlalchemy import Column, String, Integer, BLOB
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from CreateForm import CreateForm
from RegisterForm import RegisterForm
from InitForm import InitForm
import datetime
from datetime import timedelta
import random
import pyDHE
import hashlib
from ciphers import AESCipher
import requests
from ast import literal_eval

election_length = 5 #default election time in minutes
hash_len = 20 #length of SHA1 hash in bytes for assertions & int conversions

#initialize app
app = Flask(__name__)
app.secret_key = os.urandom(12).hex()
root_url = 'http://localhost:4000/'

#set up database
engine = create_engine('sqlite:///cla/sqlite/cla.db', echo=False)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=True,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()
@app.teardown_appcontext
def teardown_db(error):
    db_session.close()
    engine.dispose()

class Citizen(Base):
    #set up SQLite columns
    __tablename__ = 'citizens'
    __table_args__ = {'extend_existing': True} 
    id = Column(String, primary_key=True)
    name = Column(String)
    hash_id = Column(BLOB)
    def __init__(self, name):
        #init w/ name, create random ssn (id)
        assert len(name) > 0
        self.name = name
        ssn = str(random.SystemRandom().randint(100000000, 999999999))
        self.id = ssn
        self.hash_id = shash(ssn)

class Voter(Base):
    #set up SQLite columns
    __tablename__ = 'voters'
    __table_args__ = {'extend_existing': True} 
    hash_vn = Column(BLOB, primary_key=True)
    hash_id = Column(BLOB)
    
    def __init__(self, hash_id, vn):
        #init w/ hashed id of voter & validation number that gets hashed
        assert len(hash_id) == hash_len
        assert type(vn) == str
        self.hash_id = hash_id
        self.hash_vn = shash(vn)

class Election(Base):
    #set up SQLite columns
    __tablename__ = 'election'
    __table_args__ = {'extend_existing': True} 
    start = Column(String, primary_key=True)
    end = Column(String)
    current_time = Column(Integer)
    status = Column(String)
    
    #store when the election was created and when it will end (election_length min in the future - defined at the top)
    def __init__(self):
        start = datetime.datetime.now()
        end = start + timedelta(minutes=election_length)
        self.current_time = (end - start).seconds
        self.start = str(start)
        self.end = str(end)
        self.status = 'In progress'

    #pad the minutes/seconds with 0s for display
    def zpad(self, t):
        #ex: 5 -> 05
        t = str(t)
        if len(t) == 1: return '0' + t
        return t

    def decrement(self):
        #decrement time remaining
        #ex: 05:00 -> 04:59
        #if time left == 0, set status to finished & return 0
        sec = self.current_time
        if sec > 0:
            sec -= 1
            self.current_time = sec
            time_disp = self.zpad(sec//60) + ':' + self.zpad(sec%60)
            return time_disp
        self.status = 'Finished'
        return 0

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
        #init keys
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

#get all instances of all classes from database
def query_all_classes():
    citizens = Citizen.query.all()
    voters = Voter.query.all()
    elections = Election.query.all()
    rsakeys = RSA.query.all()
    dhke = DHKE.query.all()
    return [citizens, voters, elections, rsakeys, dhke]

#clear all instances of a given class from database
def clear_class(c):
    instances = c.query.all()
    for i in instances:
        db_session.delete(i)
    db_session.commit()

#remove all instances of all classes from database
def clear_all_classes():
    clear_class(Citizen)
    clear_class(Voter)
    clear_class(Election)

#renew DH keys
def renew_dhke():
    clear_class(DHKE)
    db_session.add(DHKE())
    db_session.commit()

#renew RSA keys
def renew_rsa():
    clear_class(RSA)
    db_session.add(RSA())
    db_session.commit()

#get shared key from another party's private key
#automatically renew public key & add it to database
def dhke_get_shared(A):
    assert type(A) == int
    dh = DHKE.query.one()
    shared = pow(int(A), int(dh.a), int(dh.p))
    db_session.delete(dh)
    db_session.add(DHKE())
    db_session.commit()
    return pow(int(A), int(dh.a), int(dh.p))

#get an instance of AES from a given Diffie Hellman shared key
#the AES key is MD5 hash of shared key
def get_aes(shared):
    assert type(shared) == int
    key = mash(str(shared))
    aes = AESCipher(key)
    return aes

#decrypt a message that has been RSA signed and AES encrypted
def decrypt(y, aes, n, e):
    '''
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
    msgs['aes_dec'] = aes.decrypt(y)
    msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), e, n).to_bytes(hash_len, byteorder='big')
    return msgs['rsa_dec']

#sign message (int) with RSA & encrypt with AES
def encrypt(x, aes):
    '''
    used for Validation Number to send back to user
    Args:
        x: number to be encrypted
        aes: AES instance

    Returns: encrypted ciphertext (bytes)
    '''
    assert type(x) == int
    rsakeys = RSA.query.one()
    msgs = {}
    msgs['intx'] = x
    msgs['rsa_enc'] = rsa.core.encrypt_int(x, int(rsakeys.d), int(rsakeys.n))
    msgs['aes_enc'] = aes.encrypt(str(msgs['rsa_enc']))
    return msgs['aes_enc']

#sign message (bytes) with RSA & encrypt with AES
def encrypt_bytes(x, shared):
    '''
    used for hashed Validation Numbers to send to CTF
    Args:
        x: bytes to be encrypted
        aes: AES instance
    Returns: encrypted ciphertext (bytes)
    '''
    assert type(shared) == int
    assert type(x) == bytes
    aes = get_aes(shared)
    intx = int.from_bytes(x, byteorder='big', signed=False)
    rsakeys = RSA.query.one()
    msgs = {}
    msgs['intx'] = intx
    msgs['rsa_enc'] = rsa.core.encrypt_int(intx, int(rsakeys.d), int(rsakeys.n))
    msgs['aes_enc'] = aes.encrypt(str(msgs['rsa_enc']))
    return msgs['aes_enc']

#home page
@app.route("/", methods=['GET', 'POST'])
def home(): 
    iform = InitForm(request.form)
    cform = CreateForm(request.form)
    rform = RegisterForm(request.form)

    #response from CLA (SSN/id or encrypted Validation Number)
    res = []

    if request.method=='POST':
        if cform.create.data and cform.validate():
            #create a new citizen with the given name
            #respond with the citizen's generated SSN/id
            citizen = Citizen(cform.name.data)
            db_session.add(citizen)
            db_session.commit()
            res.append(citizen.id)

        elif rform.register.data and rform.validate():
            '''
            Decrypt the (encrypted and hashed) id
            Then, if it's in the list of citizens' hash ids, add a new Voter & return the encrypted Validation Number
    
            Form inputs:
                e_id: encrypted SSN/id
                A: user's DH public exponent
                n, e: user's RSA public exponent and modulus
            Response: encrypted Validation Number
            '''

            e_id = literal_eval(rform.e_id.data)
            A = int(rform.A.data)
            n = int(rform.rsapub_n.data)
            e = int(rform.rsapub_e.data)
        
            shared = dhke_get_shared(A)
            aes = get_aes(shared)
            x = decrypt(e_id, aes, n, e)
            citizens = Citizen.query.all()
            voters = Voter.query.all()
            if x in [c.hash_id for c in citizens] and x not in [v.hash_id for v in voters]:
                vn = random.SystemRandom().randint(1000000000, 9999999999)
                voter = Voter(x, str(vn))
                db_session.add(voter)
                db_session.commit()
                e_vn = encrypt(vn, aes)
                res.append(e_vn)

        elif iform.init.data and iform.validate():
            #Clear all citizens and voters, renew RSA and DHKE keys, start new election, re-initialize CTF
            clear_all_classes()
            renew_rsa()
            renew_dhke()
            db_session.add(Election())
            db_session.commit()
            requests.post('http://localhost:4000/init')

    citizens, voters, elections, rsakeys, dhke = query_all_classes()
    return render_template('home.html', iform=iform, cform=cform, rform=rform, citizens=citizens, voters=voters, elections=elections, rsakeys=rsakeys, dhke=dhke, res=res)

#return list of Validation Numbers, signed & encrypted with CTF's public DH exponent, along with the public key info
@app.route("/vn-list", methods=['GET'])
def get_vn_list(): 
    #get DH public exponent from CTF
    res = requests.get('http://localhost:4000/public-keys')
    resdict = literal_eval(res._content.decode())
    A = int(resdict['A'])
    dh = DHKE.query.one()
    shared = pow(int(A), int(dh.a), int(dh.p))
    db_session.delete(dh)
    db_session.add(DHKE())
    db_session.commit()
    voters = Voter.query.all()
    e_vns = [str(encrypt_bytes(v.hash_vn, shared)) for v in voters]
    rsakeys = RSA.query.one()
    return jsonify({"e_vns": e_vns, "A": dh.public, "n": rsakeys.n, "e":rsakeys.e})

#adjust election when timer runs out
@app.route("/finish-election", methods=['POST'])
def finish_election():
    e = Election.query.one()
    e.current_time = 0
    e.status = "Finished"
    db_session.add(e)
    db_session.commit()
    return 'done'

#get election & update timer (tick down), return the countdown timer to display
@app.route("/_timer", methods=["GET", "POST"])
def timer():
    e = Election.query.one()
    new_time = e.decrement()
    if not new_time:
        finish_election()
        requests.post('http://localhost:4000/finish-election')
    db_session.add(e)
    db_session.commit()
    return jsonify({"result": new_time})

if __name__ == '__main__':
    with app.app_context():
        Base.metadata.create_all(bind=engine)       
        app.run(host="localhost", port=3000,debug=False)
