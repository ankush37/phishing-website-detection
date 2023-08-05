import numpy as np
import sklearn
import lightgbm
import catboost
import pickle
import pandas as pd
from threading import Thread
import requests
from urllib.parse import urlparse
import math
import string
from .ssl_checker import verify_cert
import whois
import datetime
from bs4 import BeautifulSoup
import re
import ipaddress
from pyquery import PyQuery
from pathlib import Path
# from googlesearch import search
# import tldextract
import warnings
warnings.filterwarnings('ignore')

BASE_DIR = str(Path(__file__).parent)

with open(BASE_DIR + "/model.pkl", "rb") as f:
    model = pickle.load(f)



TEMPORARY_DOMAIN_PLATFORMS = ["herokuapp.com","github.io","000webhostapp.com","freenom.com","repl.co","glitch.me","netlify.app",
                            "surge.sh","pages.dev","fly.dev","firebaseapp.com","awsstatic.com","azurewebsites.net","vercel.app",
                            "web.app","appspot.com","appchkr.com","blogspot.com","domains.google","hostingerapp.com","infomaniak.com",
                            "myfreesites.net","square7.ch","wixsite.com","zohosites.in","weebly.com","squarespace.com","blogger.com",
                            "tumblr.com","ghost.io","strikingly.com","jimdo.com","webflow.io","shopify.com","bigcartel.com","storenvy.com",
                            "ecwid.com","tictail.com","gumroad.com","sellfy.com","fastspring.com","sendowl.com","paddle.com","gumtree.com",
                            "mozello.com","ucraft.com","carrd.co","launchrock.com","tilda.cc","bubble.io","instapage.com",   
                            "unbounce.com","leadpages.com","getresponse.com","wordpress.com"]

class Features:
    def __init__(self, url) -> None:
        self.url = url
        self.urlparse = urlparse(url)
        self.domain = self.urlparse.netloc
        try:
            self.whois = whois.whois(self.url)
        except:
            self.whois = {}
        self.content = self.__content()
        try:
            self.pq = PyQuery(self.content.text)
        except:
            self.pq = None  

    def __content(self):
        try:
            r = requests.get(self.url, timeout=10)
            return r
        except:
            return None
    
    def domain_length(self):
        return len(self.domain)
    
    def domain_entropy(self):
        domain = urlparse(self.url).netloc
        alphabet = string.ascii_lowercase + string.digits
        freq = [0] * len(alphabet)
        for char in domain:
            if char in alphabet:
                freq[alphabet.index(char)] += 1
        entropy = 0
        for count in freq:
            if count > 0:
                freq_ratio = float(count) / len(domain)
                entropy -= freq_ratio * math.log(freq_ratio, 2)
        return round(entropy, 2)
    
    def query_params_count(self):
        query_params = self.urlparse.query.split('&')
        if query_params[0] == '':
            return 0
        else:
            return len(query_params)
        
    def path_tokens_count(self):
        path_tokens = self.urlparse.path.split('/')
        # remove empty tokens
        path_tokens = [token for token in path_tokens if token]
        return len(path_tokens)
    
    def hyphen_count(self):
        return self.url.count('-')
    
    def digits_count(self):
        return sum(c.isdigit() for c in self.url)
    
    def ssl_cert(self):
        return verify_cert(self.domain)
    
    def old(self):
        try:
            curr = datetime.datetime.now()
            creation = self.whois.get("creation_date", None)
            if creation is not None:
                days = curr - creation
                return days.days
            return -1
        except:
            return -1
    
    def temporary_domain(self):
        for i in TEMPORARY_DOMAIN_PLATFORMS:
            if i in self.url:
                return 1
        return 0
    
    def mcafee_database(self):
        url = f"https://www.siteadvisor.com/sitereport.html?url={self.url}"
        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.content, 'html.parser')
            l = soup.select("span")
            if "is safe" in l[2].text:
                return 0
            return 1
        except Exception as e: return -1
        
    def is_expired(self):
        try:
            ex = self.whois["expiration_date"] > datetime.datetime.now()
            if ex:
                return 0
            else:
                return 1
        except: return -1

    def script_to_body(self):
        try:
            soup = BeautifulSoup(self.content.content, 'html.parser')
            l = soup.find_all("script")
            total = self.content.text
            # print(type(total))
            ratio = len(l) / len(self.content.text)
            return ratio
        except Exception as e:
            # print(e)
            return -1

    def is_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return 1
        except:
            return 0
        
    def page_token(self):
        try:
            html = self.content.text.lower().split()
            return len(html)
        except:
            return -1
        
    def no_html(self):
        try:
            tags = self.pq("*")
            return len(tags)
        except:
            return -1
        
    def number_of_hidden_tags(self):
        try:
            hidden1, hidden2 = self.pq('.hidden'), self.pq('#hidden')
            hidden3, hidden4 = self.pq('*[visibility="none"]'), self.pq('*[display="none"]')
            hidden = hidden1 + hidden2 + hidden3 + hidden4
            return len(hidden)
        except:
            return -1
    
    def number_iframes(self):
        try:
            iframes = self.pq('iframe') + self.pq('frame')
            return len(iframes)
        except: return -1

    def favicon(self):
        try:
            soup = BeautifulSoup(self.content.content, 'html.parser')
            for head in soup.find_all("head"):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return 0
        except: return -1

    def abnormal_url(self):
        try:
            if self.whois.domain_name is None:
                return 1
            for i in self.whois.domain_name:
                if i in self.domain:
                    return 0
            else:
                return 1
            
        except:
            return -1
    
        
    def extract(self):
        l = [
            self.domain_length(), #0
            self.domain_entropy(), #1
            self.query_params_count(), #2
            self.path_tokens_count(), #3
            self.hyphen_count(), #4
            self.digits_count(), #5
            self.ssl_cert(), #6
            self.old(), #7
            self.temporary_domain(), #8
            self.mcafee_database(), #9
            self.is_expired(), #9
            self.script_to_body(), #10
            self.number_of_hidden_tags(), #11
            self.no_html(), #12
            self.number_iframes(), #13
            self.favicon(), #14
            self.is_ip(), #15
            self.page_token(), #16
            self.abnormal_url(), #17
        ]
        return l
    

def prediction(url):
    f = Features(url).extract()
    output_dict = {}

    if f[6] in [0,1]:
        output_dict["ssl_certificate"] = bool(f[6])
    else:
        output_dict["ssl_certificate"] = "invalid"
    
    if f[8] in [0, 1, True, False]:
        output_dict["temporary_domain"] = bool(f[8])
    else:
        output_dict["temporary_domain"] = "invalid"
    
    if f[9] in [0, 1]:
        output_dict["in mcafee database"] = bool(f[9])
    else:
        output_dict["in mcafee database"] = "invalid"
    
    if f[18] in [0,]:
        output_dict["abnormal url"] = False

    else:
        output_dict["abnormal url"] = True
        

    res = model.predict([f])[0]
    output_dict["result"] = bool(res)
    return output_dict


# print(prediction("https://noadifc9wdjfjkl.z13.web.core.windows.net/"))
