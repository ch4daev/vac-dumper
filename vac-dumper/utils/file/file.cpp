#include "file.hpp"

#include <fstream>
#include <filesystem>

namespace utils {
	namespace file {
		bool write_binary(void* binary, int size, const char* name) {
			std::fstream stream;

			stream.open(name, std::fstream::binary | std::fstream::out);

			if (stream.fail()) {
				return false;
			}

			stream.write(reinterpret_cast<char*>(binary), size);

			if (stream.fail()) {
				return false;
			}

			return true;
		}

		namespace dir {
			bool directory_exist(const char* path) {
				if (std::filesystem::exists(path)) {
					return true;
				}

				return false;
			}

			bool directory_create(const char *path) {
				if (std::filesystem::create_directory(path)) {
					return true;
				}
				return false;
			}
		}
	}
}