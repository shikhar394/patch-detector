from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import random
from bs4 import BeautifulSoup


Headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'}

BaseURL = "https://github.com/static-dev/axis"

class Cards():
  def __init__(self, githubURL):
    self.options = Options()
    self.options.add_argument("user-agent=%s"%(Headers['User-Agent']))
    self.options.add_argument('headless')
    self.driver = webdriver.Chrome(options=self.options)
    self.URL = githubURL

  def ExtractVersions(self):
    self.driver.get(self.URL)
    time.sleep(random.randint(3,6))
    self.driver.find_element_by_xpath('//button[text()="Branch:"]').click()
    time.sleep(random.randint(3,6))
    self.driver.find_element_by_xpath('//button[text()="Tags"]').click()
    print(self.driver.page_source)

Cards(BaseURL).ExtractVersions()
    
