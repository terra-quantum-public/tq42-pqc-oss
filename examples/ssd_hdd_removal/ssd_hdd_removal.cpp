#include <filesystem>
#include <fstream>
#include <iostream>

#include <pqc/delete.h>

int main()
{
    const char * filename = "testFile.txt";
    std::ofstream MyFile(filename); // create new file and fill with data
    MyFile << "-1234567890123456789qwertyuiopas";
    MyFile.close();

    PQC_file_delete(filename); // delete the file safely

    if (std::filesystem::is_regular_file(filename))
        std::cout << "file wasn't deleted";
    return 0;
}
