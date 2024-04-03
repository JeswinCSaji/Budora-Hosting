from datetime import datetime
from django.test import TestCase
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support import expected_conditions as EC
class Hosttest(TestCase):
    
    def setUp(self):
        self.driver = webdriver.Chrome()
        self.driver.implicitly_wait(10)
        self.live_server_url = 'http://127.0.0.1:8000/'

    def tearDown(self):
        self.driver.quit()
        
    def test_01_login_page(self):
        driver = self.driver
        driver.get(self.live_server_url)
        driver.maximize_window()
        time.sleep(1)
        budora=driver.find_element(By.CSS_SELECTOR,'a.nav-item.nav-link.text.animated.zoomIn[href="/login.html"]')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'input.signinelement[name="email"][placeholder="email"][required]')
        budora.send_keys("abishek@gmail.com")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'input.signinelement[type="password"][name="password"][placeholder="password"][required]')
        budora.send_keys("Abishek@123")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'.signinbtn')
        budora.click()
        time.sleep(2)
        print("Signed in successfully")
        
        budora=driver.find_element(By.CSS_SELECTOR,'#store')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#anybtn')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'.m-2')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#logz')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#logoutt')
        budora.click()
        time.sleep(2)
        alert = Alert(driver)
        alert.accept()
        
        budora=driver.find_element(By.CSS_SELECTOR,'a.nav-item.nav-link.text.animated.zoomIn[href="/login.html"]')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'input.signinelement[name="email"][placeholder="email"][required]')
        budora.send_keys("jeswincsaji@gmail.com")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'input.signinelement[type="password"][name="password"][placeholder="password"][required]')
        budora.send_keys("userpassword")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'.signinbtn')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#stock')
        budora.click()
        time.sleep(2)
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#approvestock')
        budora.click()
        time.sleep(2)


        budora=driver.find_element(By.CSS_SELECTOR,'#category')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#addcategory')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#category_name')
        budora.send_keys("Aquarium Plants")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#category_description')
        budora.send_keys("Plants that can be placed in aquarium")
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'.btn-primary')
        budora.click()
        time.sleep(2)
     
        budora=driver.find_element(By.CSS_SELECTOR,'#sellers')
        budora.click()
        time.sleep(2)
        budora=driver.find_element(By.CSS_SELECTOR,'#sellerapproval')
        budora.click()
        time.sleep(2)
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        budora=driver.find_element(By.CSS_SELECTOR,'#appr')
        budora.click()
        time.sleep(2)
        print("Seller approved successfully")
