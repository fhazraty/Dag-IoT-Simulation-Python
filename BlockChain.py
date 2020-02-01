#BlockChain.py
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class someClass:
    string = None
    num = 328965
    def __init__(self, mystring):
        self.string = mystring
    def __repr__(self):
        return self.string + "^^^" + str(self.num)

class CBlock:
    data = None
    previousTangle1Hash = None
    previousTangle2Hash = None
    previousTangle1 = None
    previousTangle2 = None
    def __init__(self, data, previousTangle1, previousTangle2):
        self.data = data
        self.previousTangle1 = previousTangle1
        self.previousTangle2 = previousTangle2
        if previousTangle1 != None:
            self.previousTangle1Hash = previousTangle1.computeHash()
        if previousTangle2 != None:
            self.previousTangle2Hash = previousTangle2.computeHash()
    def computeHash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.data),'utf8'))
        digest.update(bytes(str(self.previousTangle1Hash),'utf8'))
        digest.update(bytes(str(self.previousTangle2Hash),'utf8'))
        return digest.finalize()
    def is_valid(self):
        if self.previousTangle1 == None and self.previousTangle2 == None:
            print("Genesis Tangle detected!")
            return True

        return self.previousTangle1.computeHash() == self.previousTangle1Hash and self.previousTangle2.computeHash() == self.previousTangle2Hash

if __name__ == '__main__':
    root = CBlock('I am root', None,None)
    B1 = CBlock(b'I am a child.', root, root)
    B2 = CBlock('I am B1s brother', root, root)
    B3 = CBlock(12354, B1,B2)
    B4 = CBlock(someClass('Hi there!'),B1, B2)
    B5 = CBlock("Top block", B3,B4)

    for b in [B1, B2, B3, B4, B5]:    
        if b.is_valid():
            print ("Success! Hash is good.")
        else:
            print ("ERROR! Hash is no good.")

        
    print(B4.data)
    B4.data.num = 99999
    print(B4.data)
    if B5.is_valid():
        print ("ERROR! Couldn't detect tampering.")
    else:
        print ("Success! Tampering detected.")
    
    
    

