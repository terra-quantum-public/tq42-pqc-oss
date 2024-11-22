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

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    if (context == PQC_BAD_CONTEXT)
    {
        std::cout << "Context intialization failed" << std::endl;
    }

    if (PQC_file_delete(context, filename) != PQC_OK) // delete the file safely
    {
        std::cout << "File removal failed" << std::endl;
    }

    if (std::filesystem::is_regular_file(filename))
    {
        std::cout << "file wasn't deleted" << std::endl;
    }
    return 0;
}
