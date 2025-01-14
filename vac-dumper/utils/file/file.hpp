#pragma once

namespace utils {
	namespace file {
		bool write_binary(void* binary, int size, const char* name);

		namespace dir {
			bool directory_exist(const char* path);
			bool directory_create(const char* path);
		}
	}
}