import scrapy
from scrapy import FormRequest
from scrapy.selector import Selector
from scrapy.http import HtmlResponse

class InitSpider(scrapy.Spider):
    name = "initspider"

    urls = {
        "ch_url":"http://localhost:5000/",
        "cla_url": "http://localhost:3000/",
        "ctf_url": "http://localhost:4000/",
    }
    def start_requests(self):
        yield scrapy.Request(url=self.urls['cla_url'], callback=self.cla_init, dont_filter=True)

    def cla_init(self, response):
        yield FormRequest.from_response(response,
                                        formnumber=0,
                                        formdata={},
                                        clickdata={'name':'init'},
                                        callback = self.get_ctf,
                                        dont_filter=True)
    def get_ctf(self, response):
        yield scrapy.Request(url=self.urls['ctf_url'], callback=self.get_ch, dont_filter=True)

    def ctf_init(self, response):
        yield FormRequest.from_response(response,
                                        formnumber=0,
                                        formdata={},
                                        clickdata={'name':'init'},
                                        callback=self.get_ch,
                                        dont_filter=True)

    def get_ch(self, response):
        yield scrapy.Request(url=self.urls['ch_url'], callback=self.ch_init, dont_filter=True)

    def ch_init(self, response):
        yield FormRequest.from_response(response,
                                        formnumber=0,
                                        formdata={},
                                        clickdata={'name':'init'},
                                        callback=self.finish,
                                        dont_filter=True)
    def finish(self, response):
        return
