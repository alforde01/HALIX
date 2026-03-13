#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <iomanip>

using namespace std;

/* ---------------- OPCODE TABLE ---------------- */

map<string,int> IOT = {

{"READ",1},{"WRITE",2},{"LOAD",3},{"STORE",4},
{"ADD",5},{"SUB",6},{"MULT",7},{"DIV",8},
{"MOD",9},{"BRANCH",10},{"BRT",11},{"BRF",12},
{"CLEAR",13},{"SET",14},{"DOUBLE",15},
{"INCR",16},{"DECR",17},
{"CLT",18},{"CLE",19},{"CEQ",20},{"CNE",21},{"CGE",22},{"CGT",23},
{"SETI",24},{"ADDI",25},{"SUBI",26},
{"MULTI",27},{"DIVI",28},{"MODI",29},
{"POW",30},{"SHACC",31},
{"BSUB",32},{"RET",33},
{"HALT",99}

};

/* ---------------- SYMBOL TABLES ---------------- */

struct DataSymbol{
    int address;
    int value;
};

map<string,DataSymbol> DST;
map<string,int> ILST;

/* ---------------- TOKENIZER ---------------- */

vector<string> tokenize(string line)
{
    vector<string> tokens;
    stringstream ss(line);
    string token;

    while(ss>>token)
        tokens.push_back(token);

    return tokens;
}

/* ---------------- PASS 1 : DATA ---------------- */

void pass1(string file)
{
    ifstream in(file);

    string line;

    int address=0;

    while(getline(in,line))
    {
        auto tokens = tokenize(line);

        if(tokens.size()>1 && tokens[1]==".DATA")
        {
            int value=0;

            if(tokens.size()==3)
                value = stoi(tokens[2].substr(1));

            DST[tokens[0]]={address,value};

            address++;
        }
    }

    in.close();
}

/* ---------------- PASS 2 : LABELS ---------------- */

void pass2(string file)
{
    ifstream in(file);

    string line;

    bool code=false;

    int address=0;

    while(getline(in,line))
    {
        auto tokens = tokenize(line);

        if(tokens.size()==0) continue;

        if(tokens[0]==".BEGIN")
        {
            code=true;
            continue;
        }

        if(tokens[0]==".END")
            break;

        if(!code) continue;

        if(tokens[0].back()==':')
        {
            string label=tokens[0];
            label.pop_back();

            ILST[label]=address;
        }

        address++;
    }

    in.close();
}

/* ---------------- PASS 3 : MACHINE CODE ---------------- */

void pass3(string file)
{
    ifstream in(file);

    ofstream out("program.hlx");

    string line;

    bool code=false;

    while(getline(in,line))
    {
        auto tokens = tokenize(line);

        if(tokens.size()==0) continue;

        if(tokens[0]==".BEGIN")
        {
            code=true;
            continue;
        }

        if(tokens[0]==".END")
            break;

        if(!code) continue;

        string instr;
        int index=0;

        if(tokens[0].back()==':')
        {
            instr=tokens[1];
            index=2;
        }
        else
        {
            instr=tokens[0];
            index=1;
        }

        int opcode = IOT[instr];

        int addr=0;

        if(tokens.size()>index)
        {
            string operand = tokens[index];

            if(DST.count(operand))
                addr=DST[operand].address;

            else if(ILST.count(operand))
                addr=ILST[operand];

            else if(operand[0]=='=')
                addr=stoi(operand.substr(1));
        }

        int machine = opcode*100 + addr;

        out << setw(4) << setfill('0') << machine << endl;
    }

    in.close();
    out.close();
}

/* ---------------- MAIN ---------------- */

int main(int argc,char* argv[])
{
    if(argc<2)
    {
        cout<<"Usage: ./assembler program.hal\n";
        return 1;
    }

    string file = argv[1];

    pass1(file);
    pass2(file);
    pass3(file);

    cout<<"Assembly completed.\n";
    cout<<"Output file: program.hlx\n";

    return 0;
}