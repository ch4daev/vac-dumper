#pragma once

namespace utils {
	namespace logger {
		void init();
		void info(const char* format, ...);
		void warn(const char* format, ...);
		void fatal(const char* format, ...);
	}
}