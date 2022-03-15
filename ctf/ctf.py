from flask import Flask, render_template, request
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

hash_len = 20 #length of SHA1 hash in bytes for assertions & int conversions

#initialize app
app = Flask(__name__)
app.secret_key = os.urandom(12).hex()

#set up database
engine = create_engine('sqlite:///ctf/sqlite/ctf.db', echo=False)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=True,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()
@app.teardown_appcontext
def teardown_db(error):
    db_session.close()
    engine.dispose()

class Vote(Base):
    #set up SQLite columns
    __tablename__ = 'votes'
    __table_args__ = {'extend_existing': True} 
    hash_vn = Column(BLOB, primary_key=True)
    candidate = Column(String)
    
    def __init__(self, hash_vn, candidate):
        self.hash_vn = hash_vn
        self.candidate = candidate

class Candidate(Base):
    #set up SQLite columns
    __tablename__ = 'candidates'
    __table_args__ = {'extend_existing': True} 
    name = Column(String, primary_key=True)
    tally = Column(Integer)
    
    def __init__(self, name):
        self.name = name
        self.tally = 1

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

class Outcome(Base):
    #set up SQLite columns
    __tablename__ = 'outcomes'
    __table_args__ = {'extend_existing': True}

    result_message = Column(String, primary_key=True)
    def __init__(self, msg):
        self.result_message = msg
    def __repr__(self):
        return self.result_message

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
    candidates = Candidate.query.all()
    votes = Vote.query.all()
    rsakeys = RSA.query.all()
    dhke = DHKE.query.all()
    outcomes = Outcome.query.all()
    return [candidates, votes, rsakeys, dhke, outcomes]

#clear all instances of a given class from database
def clear_class(c):
    instances = c.query.all()
    for i in instances:
        db_session.delete(i)
    db_session.commit()

#renew RSA keys
def rsa_renew():
    clear_class(RSA)
    db_session.add(RSA())
    db_session.commit()

#renew DH keys
def dhke_renew():
    clear_class(DHKE)
    db_session.add(DHKE())
    db_session.commit()

#clear all instances of all classes, renew DHKE & RSA keys
def reset_all():
    clear_class(Candidate)
    clear_class(Vote)
    clear_class(Outcome)
    dhke_renew()
    rsa_renew()

#get an instance of AES from a given Diffie Hellman shared key
#the AES key is MD5 hash of shared key
def get_aes(shared):
    assert type(shared) == str
    key = mash(shared)
    return AESCipher(key)

#decrypt a message that has been RSA signed and AES encrypted
def decrypt(y, shared, n, e):
    '''
    used to decrypt Validation numbers from user/CLA
    Args: 
        y: ciphertext (bytes) to be decrypted
        shared: shared DHKE key
        n, e: RSA public exponent & modulus used in encryption

    Returns: decrypted int converted to bytes (b/c hashing is used before encryption)
    '''
    assert type(shared) == int
    assert type(y) == bytes
    aes = get_aes(str(shared))
    msgs = {}
    msgs['aes_enc'] = y
    msgs['aes_raw'] = aes.decrypt(msgs['aes_enc'])
    msgs['aes_dec'] = str(msgs['aes_raw']).split('\\')[0][2:]
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), int(e), int(n)).to_bytes(hash_len, byteorder='big')
    return msgs['rsa_dec']

#create the result message for an election from database info, add the Outcome to dababase
def get_election_result():
    candidates = Candidate.query.all()
    names = []
    tallies = []
    for c in candidates:
        tallies.append(c.tally)
        names.append(c.name)
    max_tally = max(tallies)
    if tallies.count(max_tally) == 1:
        ix = tallies.index(max_tally)
        result = names[ix] + ' won'
    else:
        ixs = [index for index, element in enumerate(tallies) if element == max_tally]
        result = 'tie between: ' + names[ixs.pop()]
        for i in ixs:
            result += ', ' + names[i]
    result += ' with ' + str(max_tally) + ' votes'
    o = Outcome(result)
    db_session.add(o)
    db_session.commit()
    return result

#home page
@app.route("/", methods=['GET', 'POST'])
def home(): 
    iform = InitForm(request.form)
    vform = VoteForm(request.form)

    #response from CTF (successful/unsuccessful vote)
    res = []

    outcome = Outcome.query.all()
    if request.method=='POST':
        if iform.init.data and iform.validate():
            reset_all()

        elif vform.castvote.data and vform.validate():
            if len(outcome): res.append('Election already ended')
            else:    
                '''
                decrypt the given encrypted Validation Number, request the Validation Number list from CLA,
                decrypt the Validation Number list. If it's a valid vote, add it to the list of Votes
                and adjust the list of candidate accordingly (add a new candidate or add 1 to tally)
                '''
                e_vn = literal_eval(vform.e_vn.data)
                candidate = vform.candidate.data
                A = int(vform.A.data)
                n = int(vform.n.data)
                e = int(vform.e.data)
                
                voter_dh = DHKE.query.one()
                cla_dh = DHKE()
                db_session.delete(voter_dh)
                db_session.add(cla_dh)
                db_session.commit()
                voter_shared = pow(A, int(voter_dh.a), int(voter_dh.p))
                vn_res = requests.get('http://localhost:3000/vn-list')
                resdict = vn_res.json()
                cla_A = int(resdict['A'])
                vn = decrypt(e_vn, voter_shared, n, e)
                cla_shared = pow(cla_A, int(cla_dh.a), int(cla_dh.p))
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
    return render_template('home.html', iform=iform, vform=vform, votes=votes, candidates=candidates, rsakeys=rsakeys, dhke=dhke, res=res, outcome=outcome)

@app.route("/init", methods=['POST'])
def init():
    reset_all()
    return 're-initialized'

#send DH public exponent to CLA for Validation Number list
@app.route("/public-keys", methods=['GET'])
def public_keys(): 
    dh = DHKE.query.one()
    res = {'A': dh.public}
    db_session.delete(dh)
    db_session.add(DHKE())
    return res

#get the Outcome of the election & display it
@app.route("/finish-election", methods=['POST'])
def finish_election():
    result = get_election_result()
    return result

if __name__ == '__main__':
    with app.app_context():
        Base.metadata.create_all(bind=engine)       
        app.run(host="localhost", port=4000,debug=False)
