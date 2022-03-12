from flask import Flask, redirect, render_template, request
import os
from sqlalchemy import Column, String, BLOB, Integer
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from VoteForm import VoteForm
from InitForm import InitForm
import requests
import rsa
import pyDHE
from ciphers import AESCipher
import hashlib
from ast import literal_eval

hash_len = 20

app = Flask(__name__)
skey = os.urandom(12).hex()
app.secret_key = skey

engine = create_engine('sqlite:///sqlite/ctf.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=True,
                                         bind=engine))

@app.teardown_appcontext
def teardown_db(error):
    db_session.close()
    engine.dispose()

Base = declarative_base()
Base.query = db_session.query_property()



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

class Vote(Base):
    __tablename__ = 'votes'
    __table_args__ = {'extend_existing': True} 
    hash_vn = Column(BLOB, primary_key=True)
    candidate = Column(String)
    
    def __init__(self, hash_vn, candidate):
        self.hash_vn = hash_vn
        self.candidate = candidate
    def __repr__(self):
        return f'<Vote hash vn {self.hash_vn!r}\n candidate {self.candidate!r}>'

class Candidate(Base):
    __tablename__ = 'candidates'
    __table_args__ = {'extend_existing': True} 
    name = Column(String, primary_key=True)
    tally = Column(Integer)
    
    def __init__(self, name):
        self.name = name
        self.tally = 1
    def __repr__(self):
        return f'<Candidate id {self.name!r}\n Tally = {self.tally!r}>'

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

class Outcome(Base):
    __tablename__ = 'outcomes'
    __table_args__ = {'extend_existing': True}

    result_message = Column(String, primary_key=True)

    def __init__(self, msg):
        self.result_message = msg
    def __repr__(self):
        return self.result_message

def query_all_classes():
    candidates = Candidate.query.all()
    votes = Vote.query.all()
    rsakeys = RSA.query.all()
    dhke = DHKE.query.all()
    outcomes = Outcome.query.all()
    return [candidates, votes, rsakeys, dhke, outcomes]

def clear_class(c):
    instances = c.query.all()
    for i in instances:
        db_session.delete(i)
    db_session.commit()

def rsa_renew():
    clear_class(RSA)
    db_session.add(RSA())
    db_session.commit()

def dhke_renew():
    clear_class(DHKE)
    db_session.add(DHKE())
    db_session.commit()

def dhke_get_shared(A):
    dh = DHKE.query.one()
    dhke_renew()
    return pow(int(A), int(dh.a), int(dh.p))

def get_aes(shared):
    assert type(shared) == str
    key = mash(shared)
    return AESCipher(key)

def rsa_sign(x):
    assert type(x) == int
    rsakeys = RSA.query.one()
    return rsa.core.encrypt_int(x,int(rsakeys.d),int(rsakeys.n))

def rsa_sign_encrypt(x, n, e):
    assert type(x) == int
    assert type(n) == int
    assert type(e) == int
    rsakeys = RSA.query.one()
    msgs = {}
    msgs['x'] = x
    msgs['rsa_signed'] = rsa.core.encrypt_int(x,rsakeys.d,rsakeys.n)
    msgs['rsa_enc'] = rsa.core.encrypt_int(msgs['rsa_signed'], e, n)
    return msgs

def decrypt(y, shared, n, e):
    assert type(shared) == int
    assert type(y) == bytes
    aes = get_aes(str(shared))
    msgs = {}
    msgs['aes_enc'] = y
    msgs['aes_raw'] = aes.decrypt(msgs['aes_enc'])
    msgs['aes_dec'] = str(msgs['aes_raw']).split('\\')[0][2:]
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), int(e), int(n)).to_bytes(hash_len, byteorder='big')
    return msgs['rsa_dec']

def reset_all():
    clear_class(Candidate)
    clear_class(Vote)
    clear_class(Outcome)
    dhke_renew()
    rsa_renew()

def get_election_result():
    candidates = Candidate.query.all()
    cs = []
    tallies = []
    for c in candidates:
        tallies.append(c.tally)
        cs.append(c.name)
    max_tally = max(tallies)
    if tallies.count(max_tally) == 1:
        ix = tallies.index(max_tally)
        result = cs[ix] + ' won'
    else:
        ixs = [index for index, element in enumerate(tallies) if element == max_tally]
        result = 'tie between: ' + cs[ixs[0]]
        for i in ixs:
            result += ', ' + cs[i]
    result += ' with ' + str(max_tally) + ' votes'
    o = Outcome(result)
    db_session.add(o)
    db_session.commit()
    return result

@app.route("/", methods=['GET', 'POST'])
def home(): 
    iform = InitForm(request.form)
    vform = VoteForm(request.form)
    res = []
    msgs = {}
    outcome = Outcome.query.all()
    if request.method=='POST':
        if iform.init.data and iform.validate():
            reset_all()

        elif vform.castvote.data and vform.validate():
            if len(outcome): res.append('Election already ended')
            else:    
                e_vn = literal_eval(vform.e_vn.data)
                candidate = vform.candidate.data
                A = int(vform.A.data)
                n = int(vform.n.data)
                e = int(vform.e.data)
                
                voter_shared = dhke_get_shared(A)
                vn_res = requests.get('http://localhost:3000/vn-list')
                resdict = vn_res.json()
                cla_A = resdict['A']
                vn = decrypt(e_vn, voter_shared, n, e)

                cla_shared = dhke_get_shared(cla_A)
                vn_list = [decrypt(literal_eval(v), cla_shared, resdict['n'], resdict['e']) for v in resdict['e_vns']]
                votes = Vote.query.all()
                if vn in vn_list and vn not in [v.hash_vn for v in votes]:
                    vote = Vote(vn, vform.candidate.data)
                    db_session.add(vote)
                    db_session.commit()
                    candidates = Candidate.query.all()
                    candidate = vform.candidate.data
                    if candidate not in [c.name for c in candidates]:
                        new_candidate = Candidate(candidate)
                        db_session.add(new_candidate)
                        db_session.commit()
                    else:
                        update_candidate = Candidate.query.filter_by(name=candidate).first()
                        update_candidate.tally +=1
                        db_session.add(update_candidate)
                        db_session.commit()
                    res.append('Vote successful')
                else:res.append('Vote unsuccessful')
    candidates, votes, rsakeys, dhke, outcome= query_all_classes()
    return render_template('home.html', iform=iform, vform=vform, votes=votes, candidates=candidates, rsakeys=rsakeys,
    dhke=dhke, res=res, msgs=msgs, outcome=outcome)

@app.route("/init", methods=['POST'])
def init():
    reset_all()
    return 're-initialized'

@app.route("/public-keys", methods=['GET'])
def public_keys(): 
    rsakeys = RSA.query.one()
    dh = DHKE.query.one()
    res = {'A': dh.public}
    return res

@app.route("/finish-election", methods=['POST'])
def finish_election():
    result = get_election_result()
    return result

if __name__ == '__main__':
    with app.app_context():
        Base.metadata.create_all(bind=engine)       
        app.run(host="localhost", port=4000,debug=True)
