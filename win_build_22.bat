set BUILD_DIR=build_x64_VS2022
rmdir /S /Q %BUILD_DIR%
mkdir %BUILD_DIR%
cd %BUILD_DIR%
cmake ../ -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build . --config Release
cd ..
