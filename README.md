# SC4010 SSL 3.0 POODLE Attack

<p>U/C</p>

## About
<div align="justify">
  <p>
  
  This is a Group Project for the course **SC4010 Applied Cryptography** conducted by Nanyang Technological University's College of Computing and Data Science. 
  </p>
  <p>
    
  This is a **Proof-of-Concept (PoC) demonstration** of the actual Padding Oracle on Downgraded Legacy Encryption (POODLE) attack conducted in 2014, targeting the **CVE-2014-3566** vulnerability found in client-server connections that used the **Secure Socket Layer version 3 (SSL 3.0)** protocol, which was first implemented in 1996 and deprecated in 2015. 
  </p>

**DISCLAIMER:** This PoC demonstration is solely for the purposes of learning Cryptography and particularly, the POODLE attack on SSL 3.0 protocol, and should strictly not be used, in full or part-thereof, for any malicious or unauthorised intentions, in any form.
</div>

## Getting Started

### Prerequisites
<div align="justify">
  <p>
  Before running the simulation, you will need to have the following installed on your computer:
      
  - Your preferred **Python** IDE (for this project, our group used <a href="https://code.visualstudio.com/download">VSCode IDE</a>)
  - Python packages as listed in `requirements.txt`, by running the following command:
  ```
  pip install -r requirements.txt
  ```
  *Note: For the newest Python 3.12 version, pip is not supported. Use **pip3** or **pip3.12** instead.
  - Built-in Python modules: **`hmac.py`** and **`hashlib.py`**
  </p>
  
  Fork this repo for your own convenience. :-)
</div>

### Start Attack Simulation
<div align="justify">
  <p>
    
  1. To simulate the POODLE attack, run the following command:
  
     ```
     streamlit run page_controller.py
     ```
     This will spawn the simulated account registration website running on http://localhost:8501.
      
     ![image](https://github.com/user-attachments/assets/5de6aee1-fdd7-4ca9-8666-d82493498ed2)
  </p>
  <p>
    
  2. You will be redirected to the **Account Registration Page** by default.
  
     ![image](https://github.com/user-attachments/assets/7f9f4758-328a-4565-8f3b-67a40a836e1f)
  </p>
  <p>
    
  3. Enter any set of account credentials. For the purposes of the simulation, there will not be any input validation for the username and password input fields.
  
     Upon clicking **Register**, the encrypted username and password inputs will be displayed in hexadecimal form, alongside the password in plaintext form, for demonstration purposes only.
  
     Example:
      
     ![image](https://github.com/user-attachments/assets/4430af07-c3a0-462b-bcac-72e79c33594f)
  </p>
  <p>

  4. Navigate to **Server Page** to receive the user's account credential inputs in plaintext form.

     ![image](https://github.com/user-attachments/assets/081fdf16-b28f-4ffe-a0b3-5c2209c2f155)
  </p>
  <p>
    
  5. Navigate to **Eve's Control Page** to attempt to intercept the data transfer between the user (Account Registration Page) and the server, and display the intercepted data in plaintext form.

     ![image](https://github.com/user-attachments/assets/013c24d8-7df9-4ffe-b080-832fdb11eec0)

     Finally, click **Launch Poodle Attack** to simulate the actual POODLE attack on the client-server communication.

     ![image](https://github.com/user-attachments/assets/f3672409-761e-4533-9389-f8f778e32c2e)

     You will then be able to obtain the victim's account credentials in plaintext form.

     ![image](https://github.com/user-attachments/assets/c6519d34-860b-47df-9cb5-d5675053e01e)

     ![image](https://github.com/user-attachments/assets/8c630961-ea50-4468-8645-51e95279f34d)
  </p>
</div>

## File Structure
```
├── views                                           # Codebase
|    ├── alice.py                                   # Source code for client browser
│    ├── eve.py                                     # Source code for attacker browser
│    ├── server.py                                  # Source code for web server browser
├── page_controller.py                              # Controls the navigation between the different browsers hosted on the same localhost server                
├── .gitignore
├── README.md   
└── POODLE PoC Presentation_Final.pptx              # Final presentation slide deck
```

## Presentation Slides
<div align="justify">
  You may view our presentation slide deck <a href="/POODLE PoC Presentation_Final.pptx">here</a>, for a better theoretical understanding of the POODLE attack.
</div>

## References
<div align="justify">
  <p>
    
  - https://github.com/mpgn/poodle-PoC/tree/master
  - https://access.redhat.com/articles/1232123
  - https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/
  - https://en.wikipedia.org/wiki/POODLE
  - https://www.techtarget.com/whatis/definition/POODLE-attack
  - https://www.wallarm.com/what/poodle-attack
  - https://www.manageengine.com/key-manager/information-center/what-is-poodle-attack.html
  - https://paddingoracle.github.io/
  - https://www.youtube.com/watch?v=uDHo-UAM6_4 (Padding Oracle Attack Visualization)
  - https://www.youtube.com/watch?v=F0srzSkTO5M&t=290s (POODLE attack - Padding Oracle On Downgraded Legacy Encryption (TLS Academy))
  - https://www.youtube.com/watch?v=4EgD4PEatA8&t=483s (CS2107 Padding Oracle Attack)
  </p>
</div>
