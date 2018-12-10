#include <ctime>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <cstring>

using namespace std;

#define uchar unsigned char
#define uint unsigned int

#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct
{
    uchar data[64];
    uint datalen;
    uint bitlen[2];
    uint state[8];
} SHA256_CTX;

uint k[64] =
{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA256Transform(SHA256_CTX *ctx, uchar data[])
{
    uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void SHA256Init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX *ctx, uchar data[], uint len)
{
    for (uint i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64)
        {
            SHA256Transform(ctx, ctx->data);
            DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
            ctx->datalen = 0;
        }
    }
}

void SHA256Final(SHA256_CTX *ctx, uchar hash[])
{
    uint i = ctx->datalen;

    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;

        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;

        while (i < 64)
            ctx->data[i++] = 0x00;

        SHA256Transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
    ctx->data[63] = ctx->bitlen[0];
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[60] = ctx->bitlen[0] >> 24;
    ctx->data[59] = ctx->bitlen[1];
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[56] = ctx->bitlen[1] >> 24;
    SHA256Transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i)
    {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

string SHA256(char* data)
{
    int strLen = strlen(data);
    SHA256_CTX ctx;
    unsigned char hash[32];
    string hashStr = "";

    SHA256Init(&ctx);
    SHA256Update(&ctx, (unsigned char*)data, strLen);
    SHA256Final(&ctx, hash);

    char s[3];
    for (int i = 0; i < 32; i++)
    {
        sprintf(s, "%02x", hash[i]);
        hashStr += s;
    }

    return hashStr;
}








struct TransactionData
{
    double amount;
    string senderKey;
    string receiverKey;
    time_t timestamp;
};

struct Block
{
    int index;
    string previousHash;
    vector <TransactionData> transactions;
    unsigned long long int proof;
    time_t timestamp;
};


class Blockchain
{
private:
    vector<TransactionData> current_transactions;
public:
    vector<Block> chain;

    Blockchain();

    void new_block(string previousHash);

    void new_transaction(TransactionData d);

    string generateHash(Block);

    unsigned long long int proof_of_work(unsigned long long int last_proof);

    bool valid_proof(unsigned long long int last_proof, unsigned long long int proof);

    bool validChain();

    void printBlock(Block b);
};


void Blockchain::new_block(string previousHash = "")
{
    unsigned long long int proof;

    if((int)chain.size() == 0)
        proof = 100;
    else
    {
        Block last_block = chain[chain.size() - 1];
        unsigned long long int last_proof = last_block.proof;
        proof = proof_of_work(last_proof);
    };

    time_t t1;

    TransactionData d =
    {
        1,
        "0",
        "Miner",
        time(&t1)
    };

    new_transaction(d);

    if(previousHash.empty())
        previousHash = generateHash(chain[(int)chain.size() - 1]);

    Block block =
    {
        (int)chain.size(),
        previousHash,
        current_transactions,
        proof,
        time(&t1)
    };

    current_transactions.clear();

    chain.push_back(block);
}


//Constructor
Blockchain::Blockchain()
{
    new_block("1");
}


bool Blockchain::validChain()
{
    for(int it = 1; it != (int)chain.size(); ++it)
    {
        if(generateHash(chain[it-1]) != chain[it].previousHash)
            return false;

        if(!valid_proof(chain[it-1].proof, chain[it].proof))
            return false;
    }

    return true;
}


void Blockchain::new_transaction(TransactionData d)
{
    current_transactions.push_back(d);
}


string Blockchain::generateHash(Block block)
{
    string index = to_string(block.index);
    string timestamp = to_string(block.timestamp);
    string proof = to_string(block.proof);

    string temp1, temp2, transtr;

    for(int j = 0; j != block.transactions.size(); ++j)
    {
        temp1 = to_string(block.transactions[j].amount);
        temp2 = to_string(block.transactions[j].timestamp);

        transtr += temp1 + block.transactions[j].senderKey + block.transactions[j].receiverKey + temp2;
    }

    string fin = index + timestamp + transtr + proof + block.previousHash;
    char *finStr = &(fin[0]);
    return SHA256(finStr);

}


unsigned long long int Blockchain::proof_of_work(unsigned long long int last_proof)
{
    unsigned long long int proof = 0;
    while(valid_proof(last_proof, proof) != true)
        ++proof;

    return proof;
}


bool Blockchain::valid_proof(unsigned long long int last_proof, unsigned long long int proof)
{
    string guess1 = to_string(last_proof) + to_string(proof);
    char *guess2 = &(guess1[0]);
    string guess_hash = SHA256(guess2);
    return guess_hash.substr(0, 4) == "0000";
}

void Blockchain::printBlock(Block b)
{
    cout << " Index - " << b.index << endl;
    cout << " Previous Block Hash - " << b.previousHash << endl;
    cout << " Proof - " << b.proof << endl;
    cout << " Time - " << b.timestamp << endl;

    cout << " Transactions: \n\n";

    for(int j = 0; j != b.transactions.size(); ++j)
    {
        cout << "     Amount - " << b.transactions[j].amount << endl;
        cout << "     Sender Key - " << b.transactions[j].senderKey << endl;
        cout << "     Receiver Key - " << b.transactions[j].receiverKey << endl;
        cout << "     Timestamp - " << b.transactions[j].timestamp << endl;
        cout << "\n";
    }
}

int main()                     //ORGANIZE THIS INTO .H AND .CPP FILES. PACK THE HASH CODE. UPLOAD THIS TO GITHUB
{
    Blockchain b;
    b.printBlock(b.chain[b.chain.size()-1]);


    time_t t1;
    TransactionData d1 =
    {
        1,
        "Benjo",
        "Reha",
        time(&t1)
    };

    TransactionData d2 =
    {
        4,
        "Alen",
        "Rivaldo",
        time(&t1)
    };

    b.new_transaction(d1);
    b.new_transaction(d2);

    b.new_block();

    b.printBlock(b.chain[b.chain.size()-1]);

        TransactionData d3 =
    {
        9,
        "Joe",
        "John",
        time(&t1)
    };

    TransactionData d4 =
    {
        3,
        "Beni",
        "Edo",
        time(&t1)
    };

    b.new_transaction(d3);
    b.new_transaction(d4);

    b.new_block();

    b.printBlock(b.chain[b.chain.size()-1]);

    TransactionData d5 =
    {
        2,
        "Almir",
        "Seth",
        time(&t1)
    };

    TransactionData d6 =
    {
        10,
        "Esad",
        "Vahidin",
        time(&t1)
    };

    b.new_transaction(d5);
    b.new_transaction(d6);

    b.new_block();

    b.printBlock(b.chain[b.chain.size()-1]);

    time_t t2;

    TransactionData d7 =
    {
        6,
        "Eto",
        "Gonzo",
        time(&t2)
    };

    TransactionData d8 =
    {
        1,
        "Enad",
        "Rale",
        time(&t2)
    };

    b.new_transaction(d7);
    b.new_transaction(d8);

    b.new_block();

    b.printBlock(b.chain[b.chain.size()-1]);

    cout << "Is the chain valid - " << b.validChain() << "\n \n";

    // Tampering with the chain...
    cout << "Tampering with the chain... \n\n";

    b.chain[b.chain.size()-1].previousHash = 'This is a tampered previous hash!!!';

    cout << "Now is the chain valid - " << b.validChain() << "\n\n";

    cout << "Correcting the chain...\n\n";

    b.chain[b.chain.size()-1].previousHash = b.generateHash(b.chain[b.chain.size() - 2]);

    cout << "Now is the chain valid - " << b.validChain() << "\n";

    return 0;
}

