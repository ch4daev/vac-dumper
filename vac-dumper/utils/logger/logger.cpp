#include "logger.hpp"

#include <Windows.h>
#include <stdio.h>

namespace utils {
	namespace logger {
		void init() {
			AllocConsole();

			freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
			freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
		}

		void info(const char* format, ...) {
			va_list args;
			va_start(args, format);

			char new_format[256];
			snprintf(new_format, sizeof(new_format), "[ ~ ] %s", format);

			vprintf(new_format, args);

			va_end(args);
		}

		void warn(const char* format, ...) {
			va_list args;
			va_start(args, format);

			char new_format[256];
			snprintf(new_format, sizeof(new_format), "[ * ] %s", format);

			vprintf(new_format, args);

			va_end(args);
		}

		void fatal(const char* format, ...) {
			va_list args;
			va_start(args, format);

			char new_format[256];
			snprintf(new_format, sizeof(new_format), "[ ! ] %s", format);

			vprintf(new_format, args);

			va_end(args);
		}
	}
}