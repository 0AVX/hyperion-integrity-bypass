#include <Windows.h>
#include <memory>
#include "Utils.hpp"

void Utils::Logger::Log(const std::string& Format, ...)
{
    using namespace std::string_literals;

    va_list List;
    va_start(List, Format);

    const auto Size = _vscprintf(Format.data(), List) + 1;
    const auto Buffer = std::make_unique<char[]>(Size);
    vsnprintf_s(Buffer.get(), Size, _TRUNCATE, Format.data(), List);

    va_end(List);

    OutputDebugStringA(("[IntegrityBypass] "s + Buffer.get() + '\n').c_str());
}