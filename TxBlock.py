#TxBlock
from BlockChain import CBlock
from Signatures import generate_keys, sign, verify
from Transactions import Tx
import pickle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import random
from cryptography.hazmat.primitives import hashes
import time

reward = 0.0
leading_zeros = 2
next_char_limit = 255

class TxBlock (CBlock):
    nonce = "AAAAAAA"
    def __init__(self, previousTangle1, previousTangle2):
        super(TxBlock, self).__init__([], previousTangle1, previousTangle2)
    def addTx(self, Tx_in):
        self.data.append(Tx_in)
    def removeTx(self, Tx_in):
        try:
            self.data.remove(Tx_in)
        except:
            return False
        return True
    def check_size(self):
        savePrev1 = self.previousTangle1
        savePrev2 = self.previousTangle2
        self.previousTangle1 = None
        self.previousTangle2 = None
        if len(pickle.dumps(self)) > 10000:
            self.previousTangle1 = savePrev1
            self.previousTangle2 = savePrev2
            return False
        self.previousTangle1 = savePrev1
        self.previousTangle2 = savePrev2
        return True
            
    def count_totals(self):
        total_in = 0
        total_out = 0
        for tx in self.data:
            inx = -1
            for addr, amt in tx.inputs:
                inx = inx + 1
                total_in = total_in + amt
            for addr, amt in tx.outputs:
                total_out = total_out + amt
        return total_in, total_out
    def is_valid(self):
        if not super(TxBlock, self).is_valid():
            print ("Tangle (CBlock.is_valid) returned False")
            return False
        spends={}
        #print(self.data[0].inputs)
        for tx in self.data:
            if not tx.is_valid():
                print ("Tx invalid")
                print (tx)
                return False
        if not self.check_size():
            return False
        return True
    def good_nonce(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.data),'utf8'))
        digest.update(bytes(str(self.previousTangle1),'utf8'))
        digest.update(bytes(str(self.previousTangle2),'utf8'))
        digest.update(bytes(str(self.nonce),'utf8'))
        this_hash = digest.finalize()
       
        if this_hash[:leading_zeros] != bytes(''.join([ '\x4f' for i in range(leading_zeros)]),'utf8'):
            return False
        return int(this_hash[leading_zeros]) < next_char_limit
    def find_nonce(self,n_tries=1000000):
        for i in range(n_tries):
            self.nonce = ''.join([ 
                   chr(random.randint(0,255)) for i in range(10*leading_zeros)])
            if self.good_nonce():
                return self.nonce  
        return None

def saveTangles(tangleObj, filename):
    fp = open(filename, "wb")
    pickle.dump(tangleObj, fp)
    fp.close()
    return True

def loadTangles(filename):
    fin = open(filename, "rb")
    ret = pickle.load(fin)
    fin.close()
    return ret

if __name__ == "__main__":
    pr1, pu1 = generate_keys()
    pr2, pu2 = generate_keys()
    pr3, pu3 = generate_keys()
    pr4, pu4 = generate_keys()
    pr5, pu5 = generate_keys()

    pu_indeces = {}
    
    def indexed_input(Tx_inout, public_key, amt, index_map):
        if not public_key in index_map:
            index_map[public_key] = 0            
        Tx_inout.add_input(public_key, amt)
        index_map[public_key] = index_map[public_key] + 1
    
###################Tangle Genesis#####################
    Tx1 = Tx()
    indexed_input(Tx1, pu1, 1, pu_indeces)
    Tx1.sign(pr1)

    if Tx1.is_valid():
        print("Success! Tx is valid")

    savefile = open("tx.dat", "wb")
    pickle.dump(Tx1, savefile)
    savefile.close()

    loadfile = open("tx.dat", "rb")
    newTx = pickle.load(loadfile)

    if newTx.is_valid():
        print("Success! Loaded tx is valid")
    loadfile.close()

    root = TxBlock(None,None)
    root.addTx(Tx1)
    B1 = root
    start = time.time()
    print(B1.find_nonce())
    elapsed = time.time() - start
    print("elapsed time: " + str(elapsed) + " s.")

    savefile = open("GenesisTangle.dat", "wb")
    pickle.dump(B1, savefile)
    savefile.close()

    loadfile = open("GenesisTangle.dat" ,"rb")
    load_B1 = pickle.load(loadfile)

    for b in [root, B1, load_B1]:
        print(b)
        if b.is_valid():
            print ("Success! Valid Tangle")
        else:
            print ("ERROR! Bad Tangle")

    if B1.good_nonce():
        print("Success! Nonce is good after save and load!")
    else:
        print("ERROR! Bad nonce after load")

###################Tangle2#####################
    B2 = TxBlock(B1,B1)
    Tx2 = Tx()
    indexed_input(Tx2, pu2, 1, pu_indeces)
    Tx2.sign(pr2)
    B2.addTx(Tx2)
        
    start = time.time()
    print(B2.find_nonce())
    elapsed = time.time() - start
    print("elapsed time: " + str(elapsed) + " s.")

    savefile = open("Tangle2.dat", "wb")
    pickle.dump(B2, savefile)
    savefile.close()

    loadfile = open("Tangle2.dat" ,"rb")
    load_B2 = pickle.load(loadfile)

    for b in [root, B2, load_B2]:
        print(b)
        if b.is_valid():
            print ("Success! Valid Tangle")
        else:
            print ("ERROR! Bad Tangle")

    if B2.good_nonce():
        print("Success! Nonce is good after save and load!")
    else:
        print("ERROR! Bad nonce after load")

###################Tangle3#####################
    B3 = TxBlock(B1,B1)
    Tx3 = Tx()
    indexed_input(Tx3, pu3, 1, pu_indeces)
    Tx3.sign(pr3)
    B3.addTx(Tx3)
        
    start = time.time()
    print(B3.find_nonce())
    elapsed = time.time() - start
    print("elapsed time: " + str(elapsed) + " s.")

    savefile = open("Tangle3.dat", "wb")
    pickle.dump(B3, savefile)
    savefile.close()

    loadfile = open("Tangle3.dat" ,"rb")
    load_B3 = pickle.load(loadfile)

    for b in [root, B3, load_B3]:
        print(b)
        if b.is_valid():
            print ("Success! Valid Tangle")
        else:
            print ("ERROR! Bad Tangle")

    if B3.good_nonce():
        print("Success! Nonce is good after save and load!")
    else:
        print("ERROR! Bad nonce after load")    

###################Tangle4#####################
    B4 = TxBlock(B2,B3)
    Tx4 = Tx()
    indexed_input(Tx4, pu4, 1, pu_indeces)
    Tx4.sign(pr4)
    B4.addTx(Tx4)
        
    start = time.time()
    print(B4.find_nonce())
    elapsed = time.time() - start
    print("elapsed time: " + str(elapsed) + " s.")

    savefile = open("Tangle4.dat", "wb")
    pickle.dump(B4, savefile)
    savefile.close()

    loadfile = open("Tangle4.dat" ,"rb")
    load_B4 = pickle.load(loadfile)

    for b in [root, B4, load_B4]:
        print(b)
        if b.is_valid():
            print ("Success! Valid Tangle")
        else:
            print ("ERROR! Bad Tangle")

    if B4.good_nonce():
        print("Success! Nonce is good after save and load!")
    else:
        print("ERROR! Bad nonce after load")    

###################Tangle5#####################
    B5 = TxBlock(B2,B3)
    Tx5 = Tx()
    indexed_input(Tx5, pu5, 1, pu_indeces)
    Tx5.sign(pr5)
    B5.addTx(Tx5)
        
    start = time.time()
    print(B5.find_nonce())
    elapsed = time.time() - start
    print("elapsed time: " + str(elapsed) + " s.")

    savefile = open("Tangle5.dat", "wb")
    pickle.dump(B5, savefile)
    savefile.close()

    loadfile = open("Tangle5.dat" ,"rb")
    load_B5 = pickle.load(loadfile)

    for b in [root, B5, load_B5]:
        print(b)
        if b.is_valid():
            print ("Success! Valid Tangle")
        else:
            print ("ERROR! Bad Tangle")

    if B5.good_nonce():
        print("Success! Nonce is good after save and load!")
    else:
        print("ERROR! Bad nonce after load")    


