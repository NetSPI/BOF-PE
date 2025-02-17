#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <string_view>
#include <locale>
#include <codecvt>
#include <fstream>
#include <filesystem>
#include <cstdint>
#include <beacon.h>

#include "../common/standalone.h"

typedef std::vector<char> ByteArray;

static void WriteInt(std::stringstream& ss, int value) {
    auto reversed = Reverse32(value);
    ss.write((char*)&reversed, sizeof(reversed));
}

static void WriteShort(std::stringstream& ss, short value) {
    auto reversed = Reverse16(value);
    ss.write((char*)&reversed, sizeof(reversed));
}

static void WriteBytes(std::stringstream& ss, const ByteArray& value) {
    WriteInt(ss, value.size());
    ss.write((char*)value.data(), value.size());
}

static void WriteBytes(std::stringstream& ss, const char* value, int len) {
    WriteInt(ss, len);
    ss.write(value, len);
}

static void WriteString(std::stringstream& ss, const char* str) {
    auto len = strlen(str);
    WriteInt(ss, len + 1);
    ss.write((char*)str, len + 1);
}

static void WriteString(std::stringstream& ss, const wchar_t* str) {
    auto len = wcslen(str) * 2;
    WriteInt(ss, len + 2);
    ss.write((char*)str, len + 2);
}

static void WriteString(std::stringstream& ss, const std::string& str) {
    WriteInt(ss, str.length() + 1);
    ss.write((char*)str.data(), str.length() + 1);
}

static void WriteString(std::stringstream& ss, const std::wstring& str) {
    WriteInt(ss, (str.length() + 1) * 2);
    ss.write((char*)str.data(), (str.length() + 1) * 2);
}

static void WriteString(std::stringstream& ss, const std::string_view& str) {
    WriteInt(ss, str.length() + 1);
    ss.write((char*)str.data(), str.length() + 1);
}

auto ReadFileAsString(std::string_view path) -> std::string {
    constexpr auto read_size = std::size_t(65536);
    auto stream = std::ifstream(path.data());
    stream.exceptions(std::ios_base::badbit);

    if (!stream) {
        throw std::ios_base::failure("file does not exist");
    }

    auto out = std::string();
    auto buf = std::string(read_size, '\0');
    while (stream.read(&buf[0], read_size)) {
        out.append(buf, 0, stream.gcount());
    }
    out.append(buf, 0, stream.gcount());
    return out;
}

static ByteArray ReadFileData(const std::string& file) {

    std::ifstream infile(file, std::ios::binary);

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);
    ByteArray buffer(length);
    infile.read(&buffer[0], length);
    return std::move(buffer);
}

int GetPackedArguments(int argc, const char* argv[], const char* bof_args_def, std::string& result){

    if(argc-1 > strlen(bof_args_def)){
        printf("Not enough arguments to satisfy BOF packed args with definition %s\n", bof_args_def);
        return -1;
    }

    const std::vector<std::string_view> args(argv + 1, argv + argc);
    const std::string arg_format(bof_args_def);
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::stringstream packed_args;
    int idx = 0;

    for (const auto& arg : args) {
        switch(arg_format[idx]){
        case 'Z':
            if(!std::filesystem::exists(arg))
                WriteString(packed_args, converter.from_bytes(std::string(arg)));
            else
                WriteString(packed_args, converter.from_bytes(ReadFileAsString(arg.data())));
            break;
        case 'z':
            if(!std::filesystem::exists(arg))
                WriteString(packed_args, arg);
            else{
                WriteString(packed_args, ReadFileAsString(arg.data()));
            }
            break;
        case 'i':
            WriteInt(packed_args, atoi(arg.data()));
            break;
        case 's':
            WriteShort(packed_args, (short)atoi(arg.data()));
            break;
        case 'b':
            WriteBytes(packed_args, ReadFileData(arg.data()));
            break;
        default:
            printf("Don't know how to process BOF packed arg type '%c'\n", arg_format[idx]);
            return -2;
        }
        idx++;
    }

    result = packed_args.str();
    return result.length();
}


