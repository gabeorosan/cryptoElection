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

app = Flask(__name__)
skey = os.urandom(12).hex()
app.secret_key = skey
root_url = 'http://localhost:4000/'
election_length = 5


engine = create_engine('sqlite:///sqlite/cla.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=True,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

hash_len = 20

def shash(x):
    assert type(x) == str
    sha = hashlib.sha1()
    sha.update(x.encode())
    return sha.digest()

def mash(x):
    assert type(x) == str
    m = hashlib.md5()
    m.update(x.encode())
    return m.digest()

class Citizen(Base):
    __tablename__ = 'citizens'
    __table_args__ = {'extend_existing': True} 
    id = Column(String, primary_key=True)
    name = Column(String)
    hash_id = Column(BLOB)
    def __init__(self, name):
        assert len(name) > 0
        self.name = name
        ssn = str(random.SystemRandom().randint(100000000, 999999999))
        self.id = ssn
        self.hash_id = shash(ssn)
    def __repr__(self):
        return 'Citizen {self.name!r} Id = {self.id!r} Hash Id = {self.hash_id!r}>'

class Voter(Base):
    __tablename__ = 'voters'
    __table_args__ = {'extend_existing': True} 
    hash_vn = Column(BLOB, primary_key=True)
    hash_id = Column(BLOB)
    shared = Column(String)
    
    def __init__(self, hash_id, vn, shared):
        assert len(hash_id) == hash_len
        assert type(vn) == str
        self.hash_id = hash_id
        self.shared = shared
        self.hash_vn = shash(vn)
    def __repr__(self):
        return f'<Voter id {self.hash_id!r} hash vn = {self.hash_vn!r} Shared key = {self.shared!r}>'

def zpad(t):
    t = str(t)
    if len(t) == 1: return '0' + t
    return t

class Election(Base):
    __tablename__ = 'election'
    __table_args__ = {'extend_existing': True} 
    start = Column(String, primary_key=True)
    end = Column(String)
    current_time = Column(Integer)
    status = Column(String)
    
    def __init__(self):
        start = datetime.datetime.now()
        end = start + timedelta(minutes=election_length)
        self.current_time = (end - start).seconds
        self.start = str(start)
        self.end = str(end)
        self.status = 'In progress'
    def decrement(self):
        sec = self.current_time
        if sec > 0:
            sec -= 1
            print(self.current_time)
            self.current_time = sec
            time_disp = zpad(sec//60) + ':' + zpad(sec%60)
            return time_disp

        self.status = 'Finished'
        return 0
    def __repr__(self):
        return f'<Start time {self.start!r} {self.status} {self.current_time}>'

class RSA(Base):
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
        (pubkey, privkey) = rsa.newkeys(1024)
        n, e, d, p, q, exp1, exp2, coef = privkey.__getstate__()
        self.n = str(n)
        self.e = str(e)
        self.d = str(d)
        self.p = str(p)
        self.q = str(q)
        self.exp1 = str(exp1)
        self.exp2 = str(exp2)

    def __repr__(self):
        return f'''
        <n = {self.n!r}
        e = {self.e!r} 
        d = {self.d!r}
        p = {self.p!r}
        q = {self.q!r}
        exp1 = {self.exp1!r}
        exp2 = {self.exp2!r}>
        '''

class DHKE(Base):
    __tablename__ = 'dhke'
    __table_args__ = {'extend_existing': True} 
    
    group = Column(String)
    g = Column(String)
    p = Column(String)
    a = Column(String, primary_key=True)
    public = Column(String)
    key = Column(String)
    
    def __init__(self):
        dh = pyDHE.new()
        group, g, p, a, public, key = dh.__dict__.values()
        self.group = str(group)
        self.g = str(g)
        self.p = str(p)
        self.a = str(a)
        self.public = str(public)
        self.key = str(key)

    def __repr__(self):
        return f'''
        <group = {self.group!r}
        g = {self.g!r} 
        p = {self.p!r}
        a = {self.a!r}
        public = {self.public!r}
        shared key = {self.key!r}
        '''
def query_all_classes():
    citizens = Citizen.query.all()
    voters = Voter.query.all()
    elections = Election.query.all()
    rsakeys = RSA.query.all()
    dhke = DHKE.query.all()
    return [citizens, voters, elections, rsakeys, dhke]

def clear_all_classes():
    clear_class(Citizen)
    clear_class(Voter)
    clear_class(Election)
def clear_class(c):
    instances = c.query.all()
    for i in instances:
        db_session.delete(i)
    db_session.commit()

def renew_dhke():
    clear_class(DHKE)
    db_session.add(DHKE())
    db_session.commit()
def renew_rsa():
    clear_class(RSA)
    db_session.add(RSA())
    db_session.commit()

def dhke_get_shared(A):
    dh = DHKE.query.one()
    return pow(int(A), int(dh.a), int(dh.p))

def get_aes(shared):
    assert type(shared) == int
    key = mash(str(shared))
    aes = AESCipher(key)
    return aes

def rsa_decrypt(y, n, e):
    assert type(y) == int
    assert type(n) == int
    assert type(n) == int
    return rsa.core.decrypt_int(y, e, n).to_bytes(hash_len, byteorder='big')

def decrypt(y, aes, n, e):
    assert type(y) == bytes
    assert type(n) == int
    assert type(e) == int
    msgs = {}
    msgs['aes_enc'] = y
    msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
    msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), e, n).to_bytes(hash_len, byteorder='big')
    return msgs

def encrypt(x, aes):
    assert type(x) == bytes
    assert len(x) == hash_len
    intx = int.from_bytes(x, byteorder='big', signed=False)
    rsakeys = RSA.query.one()
    msgs = {}
    msgs['x'] = x
    msgs['intx'] = intx
    msgs['rsa_enc'] = rsa.core.encrypt_int(intx, int(rsakeys.d), int(rsakeys.n))
    msgs['aes_enc'] = aes.encrypt(str(msgs['rsa_enc']))
    return msgs

def encrypt_sign(x, shared):
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

def get_validation(A, e_id, n, e):
    assert type(e_id) == bytes
    assert type(n) == int
    assert type(e) == int
    shared = dhke_get_shared(A)
    aes = get_aes(shared)
    msgs = decrypt(e_id, aes, n, e)
    citizens = Citizen.query.all()
    voters = Voter.query.all()
    if msgs['rsa_dec'] in [c.hash_id for c in citizens] and msgs['rsa_dec'] not in [v.hash_id for v in voters]:
        vn = random.SystemRandom().randint(1000000000, 9999999999)

        voter = Voter(msgs['rsa_dec'],str(vn), str(shared))
        msgs.update(encrypt(vn, aes))
        db_session.add(voter)
        db_session.commit()
        msgs['res'] = msgs['aes_enc']
    return msgs

@app.route("/", methods=['GET', 'POST'])
def home(): 
    iform = InitForm(request.form)
    cform = CreateForm(request.form)
    rform = RegisterForm(request.form)
    msgs = {}
    res = []
    if request.method=='POST':
        if cform.create.data and cform.validate():
            citizen = Citizen(cform.name.data)
            db_session.add(citizen)
            db_session.commit()
            res.append(citizen.id)

        elif rform.register.data and rform.validate():
            print(rform.e_id.data)
            e_id = literal_eval(rform.e_id.data)
            A = int(rform.A.data)
            n = int(rform.rsapub_n.data)
            e = int(rform.rsapub_e.data)
            if rform.msgs.data:
                ch_msgs = literal_eval(rform.msgs.data)
                enc_id = literal_eval(ch_msgs['aes_enc'])
                assert enc_id == e_id
                shared = dhke_get_shared(A)
                assert shared == int(ch_msgs['shared'])
                aes = get_aes(shared)
                y = e_id
                msgs['aes_enc'] = y
                msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
                msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
                msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), e, n).to_bytes(hash_len, byteorder='big')
                assert literal_eval(ch_msgs['hash']) == msgs['rsa_dec']
                citizens = Citizen.query.all()
                voters = Voter.query.all()
                assert msgs['rsa_dec']== citizens[-1].hash_id
                if msgs['rsa_dec'] in [c.hash_id for c in citizens] and msgs['rsa_dec'] not in [v.hash_id for v in voters]:
                    vn = random.SystemRandom().randint(1000000000, 9999999999)

                    voter = Voter(msgs['rsa_dec'], str(vn), str(shared))
                    rsakeys = RSA.query.one()
                    msgs = {}
                    msgs['intx'] = vn
                    msgs['rsa_enc'] = rsa.core.encrypt_int(vn, int(rsakeys.d), int(rsakeys.n))
                    msgs['aes_enc'] = aes.encrypt(str(msgs['rsa_enc']))
                    db_session.add(voter)
                    db_session.commit()
                    res.append(msgs['aes_enc'])
            else:
                shared = dhke_get_shared(A)
                aes = get_aes(shared)
                y = e_id
                msgs['aes_enc'] = y
                msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
                msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
                msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), e, n).to_bytes(hash_len, byteorder='big')
                citizens = Citizen.query.all()
                voters = Voter.query.all()
                if msgs['rsa_dec'] in [c.hash_id for c in citizens] and msgs['rsa_dec'] not in [v.hash_id for v in voters]:
                    vn = random.SystemRandom().randint(1000000000, 9999999999)

                    voter = Voter(msgs['rsa_dec'], str(vn), str(shared))
                    rsakeys = RSA.query.one()
                    msgs = {}
                    msgs['intx'] = vn
                    msgs['rsa_enc'] = rsa.core.encrypt_int(vn, int(rsakeys.d), int(rsakeys.n))
                    msgs['aes_enc'] = aes.encrypt(str(msgs['rsa_enc']))
                    db_session.add(voter)
                    db_session.commit()
                    res.append(msgs['aes_enc'])
                
            #msgs = get_validation(A, e_id, n, e)

        elif iform.init.data and iform.validate():
            clear_all_classes()
            renew_rsa()
            renew_dhke()
            db_session.add(Election())
            db_session.commit()
            requests.post('http://localhost:4000/init')
    if 'res' in msgs.keys():
        res.append(msgs['res'])
    citizens, voters, elections, rsakeys, dhke = query_all_classes()
    print(elections)
    return render_template('home.html', iform=iform, cform=cform, rform=rform, msgs=msgs, citizens=citizens, voters=voters, elections=elections, rsakeys=rsakeys, dhke=dhke, res=res)

@app.route("/vn-list", methods=['GET'])
def get_vn_list(): 
    res = requests.get('http://localhost:4000/public-keys')
    resdict = literal_eval(res._content.decode())
    A = int(resdict['A'])
    shared = dhke_get_shared(A)
    dh = DHKE.query.one()

    renew_dhke()
    voters = Voter.query.all()

    print(voters)
    e_vns = [str(encrypt_sign(v.hash_vn, shared)) for v in voters]
    rsakeys = RSA.query.one()
    
    return {'e_vns': e_vns, 'A': dh.public, 'n': rsakeys.n, 'e':rsakeys.e}

@app.route("/finish-election", methods=['POST'])
def finish_election():
    e = Election.query.one()
    e.current_time = 0
    e.status = "Finished"
    db_session.add(e)
    db_session.commit()
    print('done')
    return

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
        app.run(host="localhost", port=3000,debug=True)
