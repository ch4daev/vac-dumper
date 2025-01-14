#pragma once

#include <string>

namespace utils {
	namespace math {
		[[nodiscard]] __int32 randint();
		[[nodiscard]] std::string int_to_hexstring(int value);
	}
}