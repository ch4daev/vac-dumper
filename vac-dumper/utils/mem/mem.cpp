#include "mem.hpp"

#include <Windows.h>
#include <vector>

namespace utils {
	namespace mem {
		std::vector<int> pattern_to_byte(const char* pattern) {
			std::vector<int> pattern_bytes;

			size_t pattern_length = strlen(pattern);

			auto pattern_start = const_cast<char*>(pattern);
			auto pattern_end = pattern_start + pattern_length;

			for (auto current_byte = pattern_start; current_byte < pattern_end; ++current_byte) {
				if (*current_byte == ' ') {
					continue;
				}

				if (*current_byte == '?') {
					current_byte++;
					if (*current_byte == '?')
					{
						current_byte++;
					}

					pattern_bytes.push_back(-1);
				}
				else {
					pattern_bytes.push_back(std::strtoul(current_byte, &current_byte, 0x10));
				}
			}

			return pattern_bytes;
		}


		void* find_signature(void* base, const char* pattern) {
			if (base == nullptr) {
				return nullptr;
			}

			std::vector<int> pattern_bytes = pattern_to_byte(pattern);

			auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
			auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(dos_header->e_lfanew + reinterpret_cast<unsigned __int8*>(dos_header));
			
			auto start_address = reinterpret_cast<uint8_t*>(base);
			auto end_address = start_address + nt_header->OptionalHeader.SizeOfImage;

			size_t pattern_size = pattern_bytes.size();
			auto pattern_data = pattern_bytes.data();

			for (auto i = start_address; i < end_address - pattern_size; ++i) {
				bool found = true;

				for (int o = 0; o < pattern_size; ++o) {
					if (pattern_data[o] != -1 && i[o] != pattern_data[o]) {
						found = false;
					}
				}

				if (found) {
					return i;
				}
			}

			return nullptr;
		}		
	}
}