#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <iomanip>
#include <string>
#include <algorithm>
using namespace std;

enum OperandType { OP_NONE, OP_IMM, OP_LABEL, OP_DATA };
struct InstrInfo { int opcode; OperandType opType; };
map<string, InstrInfo>  IOT;
map<string, int>        ILST;
struct DataSymbol { int address; int value; bool hasValue; };
map<string, DataSymbol> DST;
int  allocCount = 0;
vector<string> errorLog;
bool hadError = false;

void logError(int lineNo, const string& msg)
{
    string entry = "  LINE " + to_string(lineNo) + ": ERROR - " + msg;
    cerr << entry << "\n";
    errorLog.push_back(entry);
    hadError = true;
}

bool loadConfig(const string& configFile)
{
    ifstream in(configFile);
    if(!in.is_open()){
        cerr << "ERROR: Cannot open config file: " << configFile << "\n";
        return false;
    }
    string line; int lineNo = 0;
    while(getline(in, line)){
        lineNo++;
        auto pos = line.find('#');
        if(pos != string::npos) line = line.substr(0, pos);
        istringstream ss(line);
        string mnemonic, opcodeStr, opTypeStr;
        if(!(ss >> mnemonic >> opcodeStr >> opTypeStr)) continue;
        int opcode;
        try { opcode = stoi(opcodeStr); }
        catch(...){ cerr << "CONFIG LINE " << lineNo << ": Invalid opcode for " << mnemonic << "\n"; return false; }
        OperandType opType;
        if     (opTypeStr=="NONE")  opType=OP_NONE;
        else if(opTypeStr=="IMM")   opType=OP_IMM;
        else if(opTypeStr=="LABEL") opType=OP_LABEL;
        else if(opTypeStr=="DATA")  opType=OP_DATA;
        else { cerr << "CONFIG LINE " << lineNo << ": Unknown type '" << opTypeStr << "'\n"; return false; }
        IOT[mnemonic] = {opcode, opType};
    }
    cout << "Loaded " << IOT.size() << " instructions from " << configFile << "\n";
    return true;
}

string stripComment(const string& raw)
{
    string s;
    for(size_t i=0;i<raw.size();i++){
        if(raw[i]=='#' && (i==0||raw[i-1]==' '||raw[i-1]=='\t')) break;
        s+=raw[i];
    }
    while(!s.empty()&&isspace((unsigned char)s.back())) s.pop_back();
    return s;
}

vector<string> tokenize(const string& line)
{
    vector<string> tokens;
    stringstream ss(line);
    string tok;
    while(ss>>tok) tokens.push_back(tok);
    return tokens;
}

bool isValidImmediate(const string& s)
{
    if(s.size()<2||s[0]!='=') return false;
    string rest=s.substr(1);
    if(rest.empty()) return false;
    size_t start=(rest[0]=='-')?1:0;
    if(start==rest.size()) return false;
    for(size_t i=start;i<rest.size();i++)
        if(!isdigit((unsigned char)rest[i])) return false;
    return true;
}

bool isValidIdentifier(const string& s)
{
    if(s.empty()) return false;
    if(!isalpha((unsigned char)s[0])&&s[0]!='_') return false;
    for(char c:s) if(!isalnum((unsigned char)c)&&c!='_') return false;
    return true;
}

string getBaseName(const string& path)
{
    size_t slash=path.find_last_of("/\\");
    string name=(slash==string::npos)?path:path.substr(slash+1);
    size_t dot=name.rfind('.');
    return (dot==string::npos)?name:name.substr(0,dot);
}

void pass0(const string& file)
{
    ifstream in(file);
    string raw; int lineNo=0;
    bool inData=false, inCode=false, allocSeen=false;
    while(getline(in,raw)){
        lineNo++;
        string line=stripComment(raw);
        auto tokens=tokenize(line);
        if(tokens.empty()) continue;
        string first=tokens[0];
        if(first==".ALLOC"){
            allocSeen=true; inData=true;
            if(tokens.size()<2)
                logError(lineNo,".ALLOC missing size argument — example: .ALLOC 5");
            else { try{allocCount=stoi(tokens[1]);}
                   catch(...){logError(lineNo,".ALLOC size is not an integer: "+tokens[1]);} }
            continue;
        }
        if(first==".BEGIN"){
            if(inCode) logError(lineNo,"Second .BEGIN found without intervening .END");
            inData=false; inCode=true; continue;
        }
        if(first==".END"){ inCode=false; continue; }
        if(!allocSeen && tokens.size()>=2 && tokens[1]==".DATA")
            logError(lineNo,".DATA declared before .ALLOC — .ALLOC must come first");
        if(inData && tokens.size()>=2 && tokens[1]!=".DATA")
            logError(lineNo,"Unknown directive in DATA section: "+tokens[1]);
        if(!inData&&!inCode&&first[0]=='.'&&
           first!=".ALLOC"&&first!=".BEGIN"&&first!=".END")
            logError(lineNo,"Unknown directive: "+first);
    }
}

void pass1(const string& file)
{
    ifstream in(file);
    string raw; int lineNo=0;
    bool inData=false; int address=0;
    while(getline(in,raw)){
        lineNo++;
        string line=stripComment(raw);
        auto tokens=tokenize(line);
        if(tokens.empty()) continue;
        if(tokens[0]==".ALLOC"){inData=true;continue;}
        if(tokens[0]==".BEGIN"){inData=false;continue;}
        if(tokens[0]==".END"){break;}
        if(!inData) continue;
        if(tokens.size()<2||tokens[1]!=".DATA"){
            logError(lineNo,"Expected '[name] .DATA [=val]', got: "+line); continue;}
        string varName=tokens[0];
        if(!isValidIdentifier(varName)){logError(lineNo,"Invalid variable name: "+varName);continue;}
        if(DST.count(varName)){logError(lineNo,"Duplicate variable name: "+varName);continue;}
        if(allocCount>0&&address>=allocCount){
            logError(lineNo,"Too many .DATA declarations — .ALLOC only reserved "+to_string(allocCount)+" cells");continue;}
        int value=0; bool hasValue=false;
        if(tokens.size()==3){
            string init=tokens[2];
            if(!isValidImmediate(init)) logError(lineNo,"Invalid .DATA initializer: "+init);
            else{value=stoi(init.substr(1));hasValue=true;}
        }
        DST[varName]={address,value,hasValue};
        address++;
    }
}

void pass2a(const string& file)
{
    ifstream in(file);
    string raw; int lineNo=0; bool inCode=false;
    while(getline(in,raw)){
        lineNo++;
        string line=stripComment(raw);
        auto tokens=tokenize(line);
        if(tokens.empty()) continue;
        if(tokens[0]==".BEGIN"){inCode=true;continue;}
        if(tokens[0]==".END"){break;}
        if(!inCode) continue;
        string mnemonic;
        if(tokens[0].back()==':'){
            if(tokens.size()<2){logError(lineNo,"Label with no instruction: "+tokens[0]);continue;}
            mnemonic=tokens[1];
        } else mnemonic=tokens[0];
        if(!IOT.count(mnemonic))
            logError(lineNo,"Unknown instruction mnemonic: "+mnemonic);
    }
}

void pass2b(const string& file)
{
    ifstream in(file);
    string raw; int lineNo=0; bool inCode=false; int address=0;
    while(getline(in,raw)){
        lineNo++;
        string line=stripComment(raw);
        auto tokens=tokenize(line);
        if(tokens.empty()) continue;
        if(tokens[0]==".BEGIN"){inCode=true;continue;}
        if(tokens[0]==".END"){break;}
        if(!inCode) continue;
        string mnemonic,labelName;
        if(tokens[0].back()==':'){
            labelName=tokens[0].substr(0,tokens[0].size()-1);
            if(tokens.size()<2) continue;
            mnemonic=tokens[1];
        } else mnemonic=tokens[0];
        if(!IOT.count(mnemonic)) continue;
        if(!labelName.empty()){
            if(!isValidIdentifier(labelName)) logError(lineNo,"Invalid label name: "+labelName);
            else if(ILST.count(labelName)) logError(lineNo,"Duplicate label: "+labelName);
            else ILST[labelName]=address;
        }
        address++;
    }
}

void pass3(const string& file)
{
    ifstream in(file);
    string raw; int lineNo=0; bool inCode=false;
    while(getline(in,raw)){
        lineNo++;
        string line=stripComment(raw);
        auto tokens=tokenize(line);
        if(tokens.empty()) continue;
        if(tokens[0]==".BEGIN"){inCode=true;continue;}
        if(tokens[0]==".END"){break;}
        if(!inCode) continue;
        string mnemonic; int opStart;
        if(tokens[0].back()==':'){
            if(tokens.size()<2) continue;
            mnemonic=tokens[1]; opStart=2;
        } else {mnemonic=tokens[0]; opStart=1;}
        if(!IOT.count(mnemonic)) continue;
        OperandType opType=IOT[mnemonic].opType;
        bool expectNone=(opType==OP_NONE);
        bool expectImm=(opType==OP_IMM);
        bool expectIaddr=(opType==OP_LABEL);
        bool hasOperand=((int)tokens.size()>opStart);
        if(expectNone){
            if(hasOperand) logError(lineNo,mnemonic+" takes no operand, found: "+tokens[opStart]);
            continue;
        }
        if(!hasOperand){logError(lineNo,mnemonic+" requires an operand but none was given");continue;}
        string operand=tokens[opStart];
        if(expectImm){
            if(!isValidImmediate(operand)) logError(lineNo,mnemonic+" requires immediate operand (=number), got: "+operand);
        } else if(expectIaddr){
            if(!ILST.count(operand)) logError(lineNo,mnemonic+" branch target label not found: "+operand);
        } else {
            if(operand[0]=='='){if(!isValidImmediate(operand)) logError(lineNo,"Malformed immediate: "+operand);}
            else if(!DST.count(operand)) logError(lineNo,"Undefined variable: "+operand);
        }
    }
}

void pass4(const string& file, const string& base)
{
    ifstream in(file);
    ofstream out(base+".hlx");
    ofstream lst(base+".lst");
    vector<pair<int,DataSymbol>> sorted;
    for(auto& kv:DST) sorted.push_back({kv.second.address,kv.second});
    sort(sorted.begin(),sorted.end(),[](auto&a,auto&b){return a.first<b.first;});
    lst<<"===== HALIX ASSEMBLER LISTING =====\n\n--- DATA SECTION ---\n";
    lst<<left<<setw(8)<<"Addr"<<setw(14)<<"Name"<<"Value\n"<<string(40,'-')<<"\n";
    for(auto& kv:DST)
        lst<<setw(8)<<kv.second.address<<setw(14)<<kv.first
           <<(kv.second.hasValue?to_string(kv.second.value):"(uninit)")<<"\n";
    // collect data values for legacy format (uninit = 9999)
    vector<int> dataVals;
    for(auto& p:sorted) dataVals.push_back(p.second.hasValue?p.second.value:9999);
    // count instructions with a pre-pass
    int codeSize=0;
    { ifstream tmp(file); string t; bool ic=false;
      while(getline(tmp,t)){ auto tk=tokenize(stripComment(t));
        if(tk.empty()) continue;
        if(tk[0]==".BEGIN"){ic=true;continue;}
        if(tk[0]==".END") break;
        if(!ic) continue;
        string mn=tk[0].back()==':'?(tk.size()>1?tk[1]:""):tk[0];
        if(IOT.count(mn)) codeSize++;
      }
    }
    // legacy format: codeSize first, then instructions, then dataSize, then data values
    out<<codeSize<<"\n";
    lst<<"\n--- CODE SECTION ---\n";
    lst<<left<<setw(6)<<"Line"<<setw(6)<<"Addr"<<setw(8)<<"Machine"<<"Source\n"<<string(55,'-')<<"\n";
    string raw; int lineNo=0; bool inCode=false; int address=0;
    while(getline(in,raw)){
        lineNo++;
        string line=stripComment(raw);
        auto tokens=tokenize(line);
        if(tokens.empty()) continue;
        if(tokens[0]==".BEGIN"){inCode=true;continue;}
        if(tokens[0]==".END"){break;}
        if(!inCode) continue;
        string mnemonic; int opStart;
        if(tokens[0].back()==':'){
            if(tokens.size()<2) continue;
            mnemonic=tokens[1]; opStart=2;
        } else {mnemonic=tokens[0]; opStart=1;}
        if(!IOT.count(mnemonic)) continue;
        int opcode=IOT[mnemonic].opcode;
        int addr=0;
        if((int)tokens.size()>opStart){
            string operand=tokens[opStart];
            if(DST.count(operand)) addr=DST[operand].address;
            else if(ILST.count(operand)) addr=ILST[operand];
            else if(operand[0]=='=') addr=stoi(operand.substr(1));
        }
        int machine=opcode*100+addr;
        string machOut;
        {ostringstream oss; oss<<setw(4)<<setfill('0')<<machine; machOut=oss.str();}
        out<<machOut<<"\n";
        lst<<setw(6)<<lineNo<<setw(6)<<address<<setw(8)<<machOut<<raw<<"\n";
        address++;
    }
    lst<<"\n===== END OF LISTING =====\n";
    // write data section after code (legacy format)
    out<<dataVals.size()<<"\n";
    for(int v:dataVals) out<<setw(4)<<setfill('0')<<v<<"\n";
    in.close(); out.close(); lst.close();
}

void writeLog(const string& base)
{
    ofstream log(base+".log");
    if(errorLog.empty()) log<<"Assembly completed with NO errors.\n";
    else{
        log<<"Assembly completed with "<<errorLog.size()<<" error(s):\n\n";
        for(auto& e:errorLog) log<<e<<"\n";
    }
    log.close();
}

int main(int argc, char* argv[])
{
    if(argc<2){
        cout<<"Usage: ./halixAssembler <source.hal> [config.opcode]\n";
        return 1;
    }
    string configFile=(argc>=3)?argv[2]:"halix.opcode";
    if(!loadConfig(configFile)) return 1;
    string srcFile=argv[1];
    string base=getBaseName(srcFile);
    cout<<"=== HALIX Assembler ===\nSource : "<<srcFile<<"\n\n";
    cout<<"Pass 0: Validating directives...\n"; pass0(srcFile);
    cout<<"Pass 1: Building Data Symbol Table...\n"; pass1(srcFile);
    cout<<"Pass 2a: Validating instruction mnemonics...\n"; pass2a(srcFile);
    if(hadError){cerr<<"\nERRORS found. Assembly aborted.\n";writeLog(base);return 2;}
    cout<<"Pass 2b: Building Instruction Label Symbol Table...\n"; pass2b(srcFile);
    cout<<"Pass 3: Validating operands...\n"; pass3(srcFile);
    if(hadError){cerr<<"\nERRORS found in operand validation. Assembly aborted.\n";writeLog(base);return 3;}
    cout<<"Pass 4: Generating machine code...\n"; pass4(srcFile,base);
    writeLog(base);
    cout<<"\nAssembly successful.\n";
    cout<<"Output : "<<base<<".hlx\nListing: "<<base<<".lst\nLog    : "<<base<<".log\n";
    cout<<"\n--- Data Symbol Table ---\n";
    cout<<left<<setw(14)<<"Name"<<setw(8)<<"Addr"<<"Value\n";
    for(auto& kv:DST)
        cout<<setw(14)<<kv.first<<setw(8)<<kv.second.address
            <<(kv.second.hasValue?to_string(kv.second.value):"-")<<"\n";
    cout<<"\n--- Instruction Label Table ---\n";
    cout<<left<<setw(14)<<"Label"<<"Addr\n";
    for(auto& kv:ILST) cout<<setw(14)<<kv.first<<kv.second<<"\n";
    return 0;
}
