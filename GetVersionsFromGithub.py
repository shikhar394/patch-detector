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
    self.driver = webdriver.Chrome(executable_path='/Users/shikharsakhuja/Desktop/patch-detector/chromedriver', options=self.options)
    self.URL = githubURL

  def ExtractVersions(self):
    self.driver.get(self.URL)
    time.sleep(random.randint(1,3))
    self.driver.find_element_by_xpath("//button[@class=' btn btn-sm select-menu-button js-menu-target css-truncate']").click() #Clicks the branch option
    time.sleep(random.randint(2,4))  
    self.driver.find_element_by_xpath("//button[@class='select-menu-tab-nav' and text()='Tags']").click() #Clicks the tag sub-option
    time.sleep(random.randint(2,3))  
    allVersionClasses = self.driver.find_elements_by_xpath("//span[@class='select-menu-item-text css-truncate-target']") #Collects all the versions in tags
    for Version in allVersionClasses:
      print(Version.text)
    self.driver.quit()

Cards(BaseURL).ExtractVersions()