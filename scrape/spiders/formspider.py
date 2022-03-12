import scrapy
from scrapy import FormRequest

iformdata = {}
rformdata = {"name": 'bob'}
vformdata = {}
ch_encrypt_formdata = {}
validate_formdata = {}
ch_decrypt_formdata = {}
ch_encryptvote_formdata = {}
ctf_voteform = {}
import random
candidates = ['paul buchanan', 'george hotz', 'andrej karpathy']

class QuotesSpider(scrapy.Spider):
    name = "claforms"
    
    urls = {
            "churl": "http://localhost:5000/",
            "claurl": "http://localhost:3000/",
            "ctfurl": "http://localhost:4000/",
        }
    def start_requests(self):
        yield scrapy.Request(url=self.urls['claurl'], callback=self.parse_rform)
        #yield scrapy.Request(url=self.urls['claurl'], callback=self.re_init1, dont_filter = True)
    def re_init1(self, response):
        yield FormRequest.from_response(response,
                                formnumber=0,
                                formdata=iformdata,
                                clickdata={'name': 'init'},
                                callback = self.re_init2,
                                dont_filter = True)
    def re_init2(self, response):
        yield scrapy.Request(url=self.urls['ctfurl'], callback=self.re_init3, dont_filter = True)
    def re_init3(self, response):
        yield FormRequest.from_response(response,
                                formnumber=0,
                                formdata=iformdata,
                                clickdata={'name': 'init'},
                                callback = self.re_init4,
                                dont_filter = True)
    def re_init4(self, response):
        yield scrapy.Request(url=self.urls['churl'], callback=self.re_init5, dont_filter = True)
    def re_init5(self, response):
        yield FormRequest.from_response(response,
                                formnumber=0,
                                formdata=iformdata,
                                clickdata={'name': 'init'},
                                callback = self.re_init6,
                                dont_filter = True)
    def re_init6(self, response):
        yield scrapy.Request(url=self.urls['claurl'], callback=self.parse_rform, dont_filter = True)

    def parse_rform(self, response):
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=rformdata,
                                clickdata={'name': 'register'},
                                callback=self.parse_rform_response, dont_filter = True)

    def parse_rform_response(self, response):
        res = response.body.decode()
        self.cla_A = res.split('<p>public (A) : ')[1].split('</p>')[0]
        self.id = res.split('<p>id: ')[-1].split('</p>\n')[0]
        yield scrapy.Request(url=self.urls['churl'], callback=self.parse_chform, dont_filter = True)

    def parse_chform(self, response):
        ch_encrypt_formdata['msg'] = self.id
        ch_encrypt_formdata['A'] = self.cla_A
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=ch_encrypt_formdata,
                                clickdata={'name': 'encrypt'},
                                callback=self.parse_encryptform_response, dont_filter = True)

    def parse_encryptform_response(self, response):
        res = response.body.decode()
        validate_formdata['id'] = res.split('aes_enc : ')[-1].split('<br>\n')[0]
        validate_formdata['B'] = res.split('<p>public (A) : ')[-1].split('</p>')[0]
        validate_formdata['rsapub_n'] = res.split('<p>n: ')[-1].split('</p>')[0]
        validate_formdata['rsapub_e'] = res.split('<p>e: ')[-1].split('</p>')[0]
        yield scrapy.Request(url=self.urls['claurl'], callback=self.parse_vform, dont_filter = True)

    def parse_vform(self, response):
        yield FormRequest.from_response(response,
                                formnumber=2,
                                formdata=validate_formdata,
                                clickdata={'name': 'getvalidation'},
                                callback=self.parse_vform_response)
    def parse_vform_response(self, response):
        res = response.body.decode()
        ch_decrypt_formdata['msg'] = res.split('vn&#39;: ')[-1].split('}<br>')[0].strip()
        ch_decrypt_formdata['rsapub_n'] = res.split('<p>n: ')[-1].split('</p>')[0]
        ch_decrypt_formdata['rsapub_e'] = res.split('<p>e: ')[-1].split('</p>')[0]
        yield scrapy.Request(url=self.urls['churl'], callback=self.parse_decryptform, dont_filter = True)
    
    def parse_decryptform(self, response):
        yield FormRequest.from_response(response,
                                formnumber=2,
                                formdata=ch_decrypt_formdata,
                                clickdata={'name': 'decrypt'},
                                callback=self.parse_decryptform_response)
    def parse_decryptform_response(self, response):
        res = response.body.decode()
        ch_encryptvote_formdata['msg'] = res.split('rsa_dec :')[-1].split('<br>')[0].strip()
        yield scrapy.Request(url=self.urls['ctfurl'], callback=self.parse_ctf_page, dont_filter = True)
        
    def parse_ctf_page(self, response):
        res = response.body.decode()
        ch_encryptvote_formdata['A'] = res.split('<p>public (A) :')[-1].split('</p>')[0].strip()
        yield scrapy.Request(url=self.urls['churl'], callback=self.parse_ch_form2, dont_filter = True)

    def parse_ch_form2(self, response):
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=ch_encryptvote_formdata,
                                clickdata={'name': 'encrypt'},
                                callback=self.parse_ch_form2_response)

    def parse_ch_form2_response(self, response):
        
        res = response.body.decode()
        ctf_voteform['vn'] = res.split('aes_enc :')[-1].split('<br>\n')[0].strip()
        ctf_voteform['candidate'] = random.choice(candidates)
        ctf_voteform['A'] = res.split('<p>public (A) :')[-1].split('</p>')[0].strip()
        ctf_voteform['n'] = res.split('<p>n: ')[-1].split('</p>')[0]
        ctf_voteform['e'] = res.split('<p>e: ')[-1].split('</p>')[0]
        yield scrapy.Request(url=self.urls['ctfurl'], callback=self.parse_ctf_form, dont_filter = True)

    def parse_ctf_form(self, response):
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=ctf_voteform,
                                clickdata={'name': 'castvote'},
                                callback=self.parse_ctf_form_response)
    def parse_ctf_form_response(self, response):
        return
        #print(res)
