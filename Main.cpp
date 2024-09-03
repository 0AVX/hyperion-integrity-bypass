#include <Windows.h>
#include <Utils/Utils.hpp>
#include <memory>

extern "C" 
{
	#include <Blake3/blake3.h>
}

constexpr auto Method = 3;
static_assert(Method <= 3, "Invalid method!");

const     auto Hyperion = (std::uintptr_t)GetModuleHandleA("RobloxPlayerBeta.dll");
const     auto CodeStart = Hyperion + 0xF60000;
constexpr auto CodeSize = 0xD29000;
const     auto GetEarlyDigests = (std::uint64_t(*)(std::uintptr_t, std::size_t, const std::uint32_t*, std::uint64_t, std::uint64_t, void*))(Hyperion + 0x1C29060);
const     auto EncryptPacket = Hyperion + 0x12336B0;
const     auto CachedHashes = Hyperion + 0xF3FB08;

#define CMP_MASK 0xFFFFFFFF00000000
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(VA) ((VA) & ~(PAGE_SIZE - 1))
#define VPN(VA) ((VA) >> 12) // this is a virtual page number, not a PFN.

//
// Method 1
//
using Digest = std::uint64_t[16];
Digest EarlyDigests[VFN(CodeSize)];

//
// Method 2
//
void* CodeClone;

//
// Method 3
//
template <class T>
void PatchCode(const std::uintptr_t Address, const T& Value)
{
	//
	// For this PoC, we won't support patches that exceed a page boundary.
	//
	if (PAGE_ALIGN(Address) != PAGE_ALIGN(Address + sizeof(T)))
		return;

	const auto HashBlock = [](const void* Data, const std::size_t Size, std::uint8_t* Hash)
	{
		blake3 Hasher;
		blake3_init(&Hasher);

		blake3_update(&Hasher, Data, Size);
		blake3_out(&Hasher, Hash, 32);
	};

	std::uint8_t OriginalHash[32];
	HashBlock((const void*)PAGE_ALIGN(Address), PAGE_SIZE, OriginalHash);

	std::memcpy((void*)Address, &Value, sizeof(T));

	std::uint8_t NewHash[32];
	HashBlock((const void*)PAGE_ALIGN(Address), PAGE_SIZE, NewHash);

	PROCESS_HEAP_ENTRY Entry;
	Entry.lpData = nullptr;

	//
	// While the list pointing to each hash allocation is encrypted, each hash is not.
	// This allows us to simply iterate over the heap, find the hash, and replace it.
	//
	while (HeapWalk(GetProcessHeap(), &Entry))
	{
		if (Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
		{
			if (!Entry.lpData)
				continue;

			if (std::memcmp(Entry.lpData, OriginalHash, sizeof(OriginalHash)) == 0)
				std::memcpy(Entry.lpData, NewHash, sizeof(NewHash));
		}
	}
}

LONG ExceptionHandler(PEXCEPTION_POINTERS Exception)
{
	const auto Context = Exception->ContextRecord;

	if (Context->Rip == (std::uintptr_t)GetEarlyDigests)
	{
		const auto Start = Context->Rcx;
		const auto End = Start + Context->Rdx;

		if (Start >= CodeStart && End < CodeStart + CodeSize)
		{
			Utils::Logger::Log("[Method %d] Hashing RobloxPlayerBeta.dll+%x for integrity!", Method, Start - Hyperion);

			const auto Rva = Start - CodeStart;

			if constexpr (Method == 1)
			{
				const auto EarlyDigest = *(void**)(Context->Rsp + 0x30);
				std::memcpy(EarlyDigest, &EarlyDigests[VPN(Rva)], sizeof(Digest));

				// MOV RAX, 4
				Context->Rax = 4;

				// RET
				Context->Rip = *(std::uintptr_t*)Context->Rsp;
				Context->Rsp += 8;

				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if constexpr (Method == 2)
				Context->Rcx = (std::uintptr_t)CodeClone + Rva;
		}

		// PUSH R15
		Context->Rip += 2;
		Context->Rsp -= 8;
		*(std::uint64_t*)Context->Rsp = Context->R15;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (Context->Rip == EncryptPacket)
	{
		// XOR RAX, [R12+0x20]
		Context->Rip += 5;
		Context->Rax ^= *(std::uint64_t*)(Context->R12 + 0x20);

		Utils::Logger::Log("Time: %x", *(std::uint64_t*)(Context->R12 + 0x20));
		Utils::Logger::Log("Violations: %x", *(std::uint32_t*)(Context->R12 + 0x34));

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void Main()
{
	//
	// Method 1 & 2 are updated for "version-1088f3c8e4a44cc7".
	// Method 3 doesn't require any updates.
	//

	Utils::Logger::Log("Loading using method %d!", Method);

	AddVectoredExceptionHandler(1, ExceptionHandler);

	if constexpr (Method == 1)
	{
		for (auto Page = CodeStart; Page < CodeStart + CodeSize; Page += PAGE_SIZE)
		{
			const auto Rva = Page - CodeStart;
			GetEarlyDigests(Page, PAGE_SIZE, iv, 0, CMP_MASK, &EarlyDigests[VPN(Rva)]);
		}
	}
	else if constexpr (Method == 2)
	{
		CodeClone = VirtualAlloc(nullptr, CodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!CodeClone)
			return;

		std::memcpy(CodeClone, (void*)CodeStart, CodeSize);
	}
	
	if constexpr (Method != 3)
	{
		*(std::uint8_t*)GetEarlyDigests = 0xCC;
		*(std::uint8_t*)EncryptPacket = 0xCC;
	}
	else
		PatchCode<std::uint8_t>(EncryptPacket, 0xCC);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		HMODULE Module;
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCSTR)DllMain, &Module))
			return FALSE;

		Main();
	}

	return TRUE;
}
