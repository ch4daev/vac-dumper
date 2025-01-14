#include "math.h"

#include <cstdlib>
#include <ctime>
#include <sstream>

namespace utils {
	namespace math {
		bool random_initializated = false;

		__int32 randint() {
			if (!random_initializated){
				std::srand(std::time(0));
			}

			return std::rand();
		}

		std::string int_to_hexstring(int value) {
			std::ostringstream ss;
			ss << std::hex << value;
			return ss.str();
		}
	}
}