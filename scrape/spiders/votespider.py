import scrapy
from scrapy import FormRequest
from scrapy.selector import Selector
from scrapy.http import HtmlResponse
import random
import requests
voters = ['hinata', 'kageyama', 'hoshino', 'tsukimoto', 'gon']
candidates = ['george hotz', 'andrej karpathy']
eform1 = {}
rform = {}
dform = {}
eform2 = {}
vform = {}
auto_finish = True
class VoteSpider(scrapy.Spider):
    name = "votespider"

    i = 0
    
    urls = {
            "ch_url": "http://localhost:5000/",
            "cla_url": "http://localhost:3000/",
            "ctf_url": "http://localhost:4000/",
        }
    def start_requests(self):
        yield scrapy.Request(url=self.urls['cla_url'], callback=self.submit_cform, dont_filter = True)
        
    def submit_cform(self, response):
        try: yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata={'name': voters.pop()},
                                clickdata={'name':'create'},
                                callback = self.get_eform1,
                                dont_filter = True)
        except: 
            print('finished voting')
            self.finish_election()
            return
    def get_eform1(self, response):
        eform1['msg'] = Selector(response=response).xpath('//*[@name="response"]//text()').extract()[0]
        eform1['A'] = Selector(response=response).xpath('//*[@name="A"]//text()').extract()[0]
        yield scrapy.Request(url=self.urls['ch_url'], callback=self.submit_eform, dont_filter = True)
    
    def submit_eform(self, response):
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=eform1,
                                clickdata={'name':'encrypt'},
                                callback = self.get_rform,
                                dont_filter=True)
    def get_rform(self, response):
        rform['e_id'] = Selector(response=response).xpath('//*[@name="response"]//text()').extract()[0]
        rform['A']= Selector(response=response).xpath('//*[@name="A"]//text()').extract()[0]
        rform['rsapub_n'] = Selector(response=response).xpath('//*[@name="n"]//text()').extract()[0]
        rform['rsapub_e'] = Selector(response=response).xpath('//*[@name="e"]//text()').extract()[0]
        yield  scrapy.Request(url=self.urls['cla_url'], callback=self.submit_rform, dont_filter = True)
    def submit_rform(self, response):  
        yield FormRequest.from_response(response,
                                formnumber=2,
                                formdata=rform,
                                clickdata={'name':'register'},
                                callback = self.get_dform,
                                dont_filter=True)
    def get_dform(self, response):
        dform['msg'] = Selector(response=response).xpath('//*[@name="response"]//text()').extract()[0]
        dform['rsapub_n'] = Selector(response=response).xpath('//*[@name="n"]//text()').extract()[0]
        dform['rsapub_e'] = Selector(response=response).xpath('//*[@name="e"]//text()').extract()[0]
        yield  scrapy.Request(url=self.urls['ch_url'], callback=self.submit_dform, dont_filter = True)

    def submit_dform(self, response):
        yield FormRequest.from_response(response,
                                formnumber=2,
                                formdata=dform,
                                clickdata={'name':'decrypt'},
                                callback = self.get_ctf_A,
                                dont_filter=True)
    def get_ctf_A(self, response):
        eform2['msg'] = Selector(response=response).xpath('//*[@name="response"]//text()').extract()[0]
        yield  scrapy.Request(url=self.urls['ctf_url'], callback=self.get_eform2, dont_filter = True)
    def get_eform2(self, response):
        eform2['A'] = Selector(response=response).xpath('//*[@name="A"]//text()').extract()[0]
        yield  scrapy.Request(url=self.urls['ch_url'], callback=self.submit_eform2, dont_filter = True)
    def submit_eform2(self, response):
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=eform2,
                                clickdata={'name':'encrypt'},
                                callback = self.get_vform,
                                dont_filter=True)
    def get_vform(self, response):
        vform['A'] = Selector(response=response).xpath('//*[@name="A"]//text()').extract()[0]
        vform['candidate'] = random.choice(candidates)
        vform['e_vn'] = Selector(response=response).xpath('//*[@name="response"]//text()').extract()[0]
        vform['n'] = Selector(response=response).xpath('//*[@name="n"]//text()').extract()[0]
        vform['e'] = Selector(response=response).xpath('//*[@name="e"]//text()').extract()[0]
        yield  scrapy.Request(url=self.urls['ctf_url'], callback=self.submit_vform, dont_filter = True)
    def submit_vform(self, response):
        yield FormRequest.from_response(response,
                                formnumber=1,
                                formdata=vform,
                                clickdata={'name':'castvote'},
                                callback = self.iterate,
                                dont_filter=True)
    def iterate(self, response):
        yield scrapy.Request(url=self.urls['cla_url'], callback=self.submit_cform, dont_filter = True)
    def finish_election(self):
        if auto_finish:
            requests.post('http://localhost:4000/finish-election')
            requests.post('http://localhost:3000/finish-election')
        print('done')
        return
