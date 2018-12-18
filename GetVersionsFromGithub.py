from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import random
from bs4 import BeautifulSoup
import json
import sys
from pprint import pprint

Headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'}
BaseURL = "https://github.com/static-dev/axis"
if len(sys.argv) < 2:
  exit("Usage: python3 GetVersionsFromGithub.py SNYKData.json")

class VersionsForURLs():
  def __init__(self, githubURL_List):
    self.options = Options()
    self.options.add_argument("user-agent=%s"%(Headers['User-Agent']))
    #self.options.add_argument('headless')
    self.driver = webdriver.Chrome(executable_path='/Users/shikharsakhuja/Desktop/patch-detector/chromedriver', options=self.options)
    self.URLs = githubURL_List

  def ExtractVersions(self):
    URL_Version_Dict = {}
    for URL in self.URLs:
      print("Extracting versions for", URL)
      Versions = []
      self.driver.get(URL)
      time.sleep(random.randint(1,3))
      self.driver.find_element_by_xpath("//button[@class=' btn btn-sm select-menu-button js-menu-target css-truncate']").click() #Clicks the branch option
      time.sleep(random.randint(2,4))  
      self.driver.find_element_by_xpath("//button[@class='select-menu-tab-nav' and text()='Tags']").click() #Clicks the tag sub-option
      time.sleep(random.randint(2,3))  
      allVersionClasses = self.driver.find_elements_by_xpath("//span[@class='select-menu-item-text css-truncate-target']") #Collects all the versions in tags
      for Version in allVersionClasses:
        Versions.append(Version.text)
      URL_Version_Dict[URL] = Versions
    self.driver.quit()
    return URL_Version_Dict

def GetRelevantURLs(snyk_data):
  repo_addresses = set()
  for item in snyk_data:
    for vulnerability in snyk_data[item]:
      repo_address = ""
      for ref in vulnerability["references"]:
        if "commit" in ref["url"]:
          url_parts = ref["url"].split("/commits/")
          if len(url_parts) < 2:
            url_parts = ref["url"].split("/commit/")
          repo_address = url_parts[0].split("/pull/")[0]
          if 'github' in repo_address:
            repo_addresses.add(repo_address)
  return repo_addresses

if __name__ == "__main__":
  SNYK_Data = json.load(open(sys.argv[1]))
  URLs = GetRelevantURLs(SNYK_Data)
  URL_Version_Dict = VersionsForURLs(URLs).ExtractVersions()
  with open("URL_to_Versions.json", 'a') as f:
    json.dump(URL_Version_Dict, f, indent=4)



  #Cards(BaseURL).ExtractVersions()