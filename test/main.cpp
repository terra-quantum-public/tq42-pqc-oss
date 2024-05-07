#include <gtest/gtest.h>

#if defined(_MSC_VER) && defined(_DEBUG)
#include <iostream>
#include <windows.h>

static int CrtReportHook(int reportType, char * message, int * returnValue)
{
    std::cerr << message << std::endl;
    ExitProcess(1); /// No need to waste any more time.
    // *returnValue = TRUE; /// Generate exception.
    // return TRUE; /// Handled.
}
#endif

int main(int argc, char ** argv)
{
    testing::InitGoogleTest(&argc, argv);

#if defined(_MSC_VER) && defined(_DEBUG)
    if (!IsDebuggerPresent())
    {
        _CrtSetReportHook(CrtReportHook);
    }
#endif

    return RUN_ALL_TESTS();
}
