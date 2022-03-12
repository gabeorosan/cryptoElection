from sys import byteorder
from flask import Flask, redirect, render_template, request, flash, url_for, make_response, jsonify
from flask_restful import reqparse, abort, Api, Resource
import os
from sqlalchemy import Column, String, Integer
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from InitForm import InitForm
from EncryptForm import EncryptForm
from DecryptForm import DecryptForm
import datetime
import random
import requests
import rsa
from ciphers import AESCipher 
import hashlib
import pyDHE

app = Flask(__name__)
app.secret_key = os.urandom(12).hex()


engine = create_engine('sqlite:///sqlite/ch.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=True,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

hash_len = 20

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

def dhke_get_shared(A):
    assert type(A) == int
    dh = DHKE.query.one()
    shared = str(pow(int(A), int(dh.a), int(dh.p)))
    dh.key = shared
    db_session.add(dh)
    db_session.commit()
    return shared

def clear_class(c):
    instances = c.query.all()
    for i in instances:
        db_session.delete(i)

    db_session.commit()
def dhke_renew():
    clear_class(DHKE)
    db_session.add(DHKE())
    db_session.commit()

def rsa_renew():
    clear_class(RSA)
    db_session.add(RSA())
    db_session.commit()

def get_aes(shared):
    assert type(shared) == str 
    aes = AESCipher(mash(shared))
    return aes

def encrypt(x, aes):
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
    msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
    msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
    print(repr(msgs['aes_dec']))
    print(rsakeys.e, rsakeys.n)
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), int(rsakeys.e), int(rsakeys.n)).to_bytes(hash_len, byteorder='big')
    return msgs

def decrypt(y, aes, n, e):
    assert type(y) == bytes
    assert len(y) == hash_len
    assert type(n) == int
    assert type(e) == int
    msgs = {}
    msgs['aes_enc'] = y
    msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
    msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
    msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), int(e), int(n)).to_bytes(hash_len, byteorder='big')
    return msgs

@app.route("/", methods=['GET', 'POST'])
def home():
    iform = InitForm(request.form)
    eform = EncryptForm(request.form)
    dform = DecryptForm(request.form)
    msgs = {}
    res = []
    if request.method=='POST':
        if iform.init.data and iform.validate():
            rsa_renew()
            dhke_renew()
        elif eform.encrypt.data and eform.validate():
            A = int(eform.A.data)
            shared = dhke_get_shared(A)
            aes = get_aes(shared)
            msg = eval(eform.msg.data)
            if type(msg) == bytes:
                msg = int.from_bytes(msg, 'big')
            
            msgs = encrypt(str(msg), aes)
            res.append(msgs['aes_enc'])
        elif dform.decrypt.data and dform.validate():
            n = int(dform.rsapub_n.data)
            e = int(dform.rsapub_e.data)
            msg = dform.msg.data
            dh = DHKE.query.all()[0]
            shared = int(dh.key)
            aes = get_aes(str(shared))
            y = eval(msg)
            assert type(y) == bytes
            assert type(n) == int
            assert type(e) == int
            msgs = {}
            msgs['aes_enc'] = y
            msgs['aes_dec'] = aes.decrypt(msgs['aes_enc'])
            msgs['aes_dec'] = str(msgs['aes_dec']).split('\\')[0][2:]
            print(msgs['aes_dec'])
            msgs['rsa_dec'] = rsa.core.decrypt_int(int(msgs['aes_dec']), int(e), int(n)).to_bytes(hash_len, byteorder='big')
            res.append(msgs['rsa_dec'])

            if len(res) > 0:
                if type(res[0]) == bytes:
                    res[0] = int.from_bytes(res[0], 'big')

    rsakeys = RSA.query.all()
    dhke = DHKE.query.all()
    return render_template('home.html', iform=iform, eform=eform, dform=dform, rsakeys=rsakeys, dhke=dhke, msgs=msgs,
    res=res)

if __name__ == '__main__':
    with app.app_context():
        Base.metadata.create_all(bind=engine)       
        app.run(host="localhost", port=5000,debug=True)
