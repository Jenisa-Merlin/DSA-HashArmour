/**SHA 256 - SECURE HASH ALGORITHM 256
  *21PW02 - AKEPATI JYOSHNA REDDY
  *21PW08 - JENISA MERLIN D
  *HASHING AND SALTING PASSWORDS
**/

#include <iostream>
#include <cstring>
#include <fstream>
#include <cstdlib>
#include <list>
#include <string.h>

using namespace std;

const int sizeH = 200;

//creating hashtable
class HashTable
{
    int key;
    string *str;
    list<string> *table;
public:
    HashTable(string *pwd)
    {
        int length = pwd->size();
        this->str = new string[length];
    }
    HashTable()
    {
        this->table = new list<string> [sizeH];
    }
    int hashFunc()
    {
        key = rand();
        return  key % sizeH;
    }
    void InsertHash(string *pwd)
    {
        int index = hashFunc();
        table[index].push_back(*pwd);
    }
};
void check(string );
//class hashing
class Hashing
{
    protected:
        typedef unsigned char uchar;
        typedef unsigned int uint;
        typedef unsigned long long ull;
        const static uint k[]; //constant
        static const unsigned int hashBlkSize = (512/8);
        void hashTransform(const unsigned char *message, unsigned int blockNb);
        unsigned int msgTotLen;
        unsigned int msgLen;
        unsigned char msgBlock[2*hashBlkSize];
        uint hashMsg[8];
    public:
        void initHash();
        void Hashupdate(const unsigned char *message, unsigned int len);
        void hashOutput(unsigned char *hashed);
        static const unsigned int hashedSize = ( 256 / 8);
};

///Hashing algorithms
/**Modify the zero-ed indexes at the end of the array using the following algorithm:
For i from w[16…63]:
s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
w[i] = w[i-16] + s0 + w[i-7] + s1
**/

#define unpackingHash(x, str){*((str) + 3) = (uchar) ((x)      );*((str) + 2) = (uchar) ((x) >>  8);*((str) + 1) = (uchar) ((x) >> 16);*((str) + 0) = (uchar) ((x) >> 24);}


#define hashPacking(str, x){*(x) =    ((uint) *((str) + 3)      )| ((uint) *((str) + 2) <<  8)| ((uint) *((str) + 1) << 16)| ((uint) *((str) + 0) << 24);}


#define HASHING_SHFR(x, n)    (x >> n)
#define HASHING_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define HASHING_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define HASHING_CH(x, y, z)  ((x & y) ^ (~x & z))
#define HASHING_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define HASHING_F1(x) (HASHING_ROTR(x,  2) ^ HASHING_ROTR(x, 13) ^ HASHING_ROTR(x, 22))
#define HASHING_F2(x) (HASHING_ROTR(x,  6) ^ HASHING_ROTR(x, 11) ^ HASHING_ROTR(x, 25))
#define HASHING_F3(x) (HASHING_ROTR(x,  7) ^ HASHING_ROTR(x, 18) ^ HASHING_SHFR(x,  3))
#define HASHING_F4(x) (HASHING_ROTR(x, 17) ^ HASHING_ROTR(x, 19) ^ HASHING_SHFR(x, 10))




/**
  Creating a constant k which has 64 values each value is the first 32 bits of fractional parts of cube roots of first 64 primes
**/
const unsigned int Hashing::k[64] = {   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5 , 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3 , 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc , 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7 , 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13 , 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3 , 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5 , 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208 , 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


/**
Initialize variables a, b, c, d, e, f, g, h and set them equal to the current hash values respectively. h0, h1, h2, h3, h4, h5, h6, h7
Run the compression loop. The compression loop will mutate the values of a…h. The compression loop is as follows:
for i from 0 to 63
S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
ch = (e and f) xor ((not e) and g)
temp1 = h + S1 + ch + k[i] + w[i]
S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
maj = (a and b) xor (a and c) xor (b and c)
temp2 := S0 + maj
h = g
g = f
f = e
e = d + temp1
d = c
c = b
b = a
a = temp1 + temp2
**/

void Hashing :: hashTransform(const unsigned char *message, unsigned int blockN)
{
    uint w[64];
    uint wv[8];
    uint t1, t2;
    const unsigned char *subBlk;
    int i,j;
    for(i=0; i<blockN; i++)
    {
        subBlk = message + (i << 6);
        for(j=0; j<16; j++)
        {
            hashPacking(&subBlk[j << 2], &w[j]);
        }
        for(j=16; j<64; j++)
        {
            w[j] =  HASHING_F4(w[j -  2]) + w[j -  7] + HASHING_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++)
        {
            wv[j] = hashMsg[j];
        }
        for (j = 0; j < 64; j++)
        {
            t1 = wv[7] + HASHING_F2(wv[4]) + HASHING_CH(wv[4], wv[5], wv[6]) + k[j] + w[j];
            t2 = HASHING_F1(wv[0]) + HASHING_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++)
        {
            hashMsg[j] += wv[j];
        }
    }
}

void Hashing :: initHash()
{
    ///Initialize the hash values which is representing the first 32 bits of fractional parts of the square roots of
    ///first 8 primes(2,3,5,7,11,13,17,19)

    hashMsg[0] = 0x6a09e667;
    hashMsg[1] = 0xbb67ae85;
    hashMsg[2] = 0x3c6ef372;
    hashMsg[3] = 0xa54ff53a;
    hashMsg[4] = 0x510e527f;
    hashMsg[5] = 0x9b05688c;
    hashMsg[6] = 0x1f83d9ab;
    hashMsg[7] = 0x5be0cd19;
    msgLen = 0;
    msgTotLen = 0;
}

//password is converted into string and sent as parameter
void Hashing::Hashupdate(const unsigned char *message, unsigned int len)
{
    unsigned int blockN;
    unsigned int newLen,remLen,tempLen;
    const unsigned char *shiftMsg;
    tempLen = hashBlkSize- msgLen;
    remLen = len < tempLen ? len : tempLen;
    //memory copying
    //memcpy(destination,source,size)
    memcpy(&msgBlock[msgLen], message, remLen);
    if(msgLen + len < hashBlkSize)
    {
        msgLen += len;
        return ;
    }
    newLen = len - remLen;
    blockN = newLen / hashBlkSize;
    shiftMsg = message + remLen;
    hashTransform(msgBlock,1);
    hashTransform(shiftMsg, blockN);
    remLen = newLen % hashBlkSize;
    ///memory copy
    memcpy(msgBlock, &shiftMsg[blockN << 6], remLen);//memcpy(destination,source,sizeCount)
    msgLen = remLen;
    msgTotLen += (blockN + 1) << 6;
}

/**
After the compression loop, but still, within the chunk loop, we modify the hash values by adding their respective variables
to them, a-h. As usual, all addition is modulo 2^32.

**/

void Hashing :: hashOutput(unsigned char *hashed)
{
    unsigned int blockN;
    unsigned int permLen;
    unsigned int lenB;
    int i;
    blockN = (1 + ((hashBlkSize - 9) < (msgLen % hashBlkSize)));
    lenB = (msgTotLen + msgLen) << 3;
    permLen = blockN << 6;
    ///memory allocating
    memset(msgBlock + msgLen, 0, permLen - msgLen);//memset(destination,character,count)
    msgBlock[msgLen] = 0x80;
    unpackingHash(lenB, msgBlock + permLen - 4);
    hashTransform(msgBlock, blockN);
    for(i=0; i<8; i++)
    {
        unpackingHash(hashMsg[i], &hashed[i << 2]);
    }
}

string hashing(string passwd)
{
    int i;
    //array of character of size 32
    unsigned char hashed[Hashing::hashedSize];
    //allocating memory memset(destination = hashed,0,size = size of hashed)
    ///filling the remaining hashed array with 0
    memset(hashed,0,Hashing::hashedSize);
    Hashing HT; //creating object for Hashing class
    HT.initHash(); //initial step
    HT.Hashupdate((unsigned char*)passwd.c_str(),passwd.length()); //update hash
    HT.hashOutput(hashed); //hashed password
    char buffer[2 * Hashing::hashedSize + 1]; //buffer to store the hashing password temporarily
    buffer[2 * Hashing::hashedSize] = 0;
    for(i=0; i<Hashing::hashedSize; i++)
    {
        sprintf(buffer + i * 2, "%02x", hashed[i]); //converting the given string to its octal form using sprintf c function
    }
    return (buffer); //return buffer which contains the salted password
}

///main begins
void check(string passwd)
{
    HashTable h;
    string line;
    string hashpasswd;
    int flag =0,r;
    ifstream infile;
        infile.open("Hash.txt",ios::in);
        {
            while(!infile.eof())
            {
                getline(infile,line);
                if(strcmp(passwd.c_str(),line.c_str())== 0)
                 {
                    cout<<endl;
                    cout<<"Already exsisting"<<endl;
                    flag = 1;
                    break;
                 }
                 else
                 {
                     getline(infile,line);
                     getline(infile,line);
                 }
            }

        }
        infile.close();
        if(flag == 0)
        {
            hashpasswd = hashing(passwd);
            cout<<"Hashed password of "<<passwd<<" is : "<<hashpasswd<<endl;
            ofstream outfile;
            outfile.open("Hash.txt",ios::app);
            if(!outfile)
            {
                cout<<"Error";
            }
            else
            {
                cout<<"File opened";
                outfile<<passwd<<endl;
                outfile << hashpasswd << endl;
            }

            h.InsertHash(&hashpasswd);
        }
        else
        {
            cout<<"Enter another username:";
            cin>>passwd;
            check(passwd);
        }
}
int main()
{
    int flag =0;
    HashTable h;
    string line;
    string passwd,hashpasswd;
    char choice = 'y';
    do
    {
        cout<<"Enter the password to be hashed : ";
        //getline(cin,passwd);
        cin>>passwd;
        check(passwd);
        cout<<"Do you want to continue ? ";
        cin>>choice;
        system("CLS");
    }while(choice == 'y' || choice == 'Y');
    return 0;
}
