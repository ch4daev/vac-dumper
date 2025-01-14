#include "dumper.hpp"

#include "utils/utils.hpp"
#include "thirdparty/minhook/MinHook.h"

#include <Windows.h>
#include <string>

namespace dumper {

	namespace hooked {

		struct mapped_module_info {
			__int8 padding[20];
			void* pointer;
		};

		struct vac_modules_mapped_list {
			mapped_module_info * vac_module_info;
		};

		struct vac_modules_info {
			__int32 padding1;
			__int32* shellcode_index;
			__int32 padding2[9];
			vac_modules_mapped_list mapped_list;
		};

		/*
			structure used by CStdMemAlloc in steamservice for memory control
		*/
		struct LMEM_INFO
		{
			__int32 padding1;
			__int32* ModuleBase;
		};

		/*
			structure contains module info for vac module mapped on client,
			fills while module mapping
		*/
		struct vac_module_info
		{
			__int32 padding[2];
			LMEM_INFO* m_pModule;
			__int32* runfunc;
			__int32 adding1;
			__int32 module_binary_size;
			__int32* module_binary_buffer;
		};


		// packet struct recv from server
		struct vac_packet {
			unsigned __int32 padding1[50];
			vac_modules_info * modules_info;
			__int32 padding2;
			int number;
			unsigned __int32 padding3[2];
			int code;
			__int32 padding;
			void* input_buffer;
			int input_buffer_size;
			void* output_buffer;
			__int32 output_buffer_size;
		};

		// structure for output packet file
		struct vac_packet_file {
			__int32 code;
			__int32 input_buffer_size;
			__int32 out_buffer_size;
			/*
				here placed input packet data,
				have volatile size
			*/
		};

		/*
			typedef for function searches for structure of already mapped vac module in memory, 
			if it does not find it, it returns -1

			TODO : implement native
		*/
		typedef int (__thiscall* find_vac_module_info_index_t)(void*, int*);
		find_vac_module_info_index_t find_vac_module_info_index = nullptr;
		

		typedef void* (__thiscall* VacModuleExecute_t)(void*, int);
		VacModuleExecute_t oVacModuleExecute;

		void* __fastcall hVacModuleExecute(vac_packet* th, int a2) {
			/*
				tries to find structure index for vac module mapped into memory

				if module not mapped to memory, return code -1
			*/

			__int32 module_index = find_vac_module_info_index(&th->modules_info->shellcode_index, &th->number);
			//__int32 module_index = find_vac_module_info_index(th->modules_info + 1, &th->number);

			/*
				module not mapped, returning to original function
			*/
			if (module_index == -1) {
				//utils::logger::info("%s \n", "fuck -1");
				return oVacModuleExecute(th, a2);
			}

			/*
				display many debug info about received packet
			*/
			utils::logger::info(" %s %d \n", "code ->", th->code);
			utils::logger::info(" %s 0x%p \n", "input_buffer ->", th->input_buffer);
			utils::logger::info(" %s 0x%p \n", "input_buffer_size ->", th->input_buffer_size);
			utils::logger::info(" %s 0x%p \n", "out_buffer_size ->", th->output_buffer_size);

			/*
				every module has own entry in array, we get pointer to structure by index
			*/
			vac_module_info* module_info = reinterpret_cast<vac_module_info*>(th->modules_info->mapped_list.vac_module_info[module_index].pointer);

			/*
				calculating packet dump size
			*/

			size_t packet_size = sizeof(vac_packet_file) + th->input_buffer_size; 

			/*
				allocating buffer for packet dump
			*/

			unsigned __int8* packet = new unsigned __int8[packet_size];

			if (packet == nullptr) {
				utils::logger::fatal("%s \n", "failed buffer allocation for packet dump :(");

				return oVacModuleExecute(th, a2);
			}

			/*
				copy all info to buffer
			*/

			auto packet_struct = reinterpret_cast<vac_packet_file*>(packet);

			packet_struct->code = th->code;
			packet_struct->input_buffer_size = th->input_buffer_size;
			packet_struct->out_buffer_size = th->output_buffer_size;

			std::memcpy(packet + sizeof(vac_packet_file), th->input_buffer, th->input_buffer_size);

			unsigned __int8* vac_module = nullptr;
			size_t vac_module_size = NULL;

			/*
				if module has not been mapped, pointer to runfunc will be nullptr, in this case we dump module
			*/

			if (module_info->runfunc == nullptr) { // module not mapped, dumping...

				vac_module_size = module_info->module_binary_size;

				vac_module = new unsigned __int8[vac_module_size];

				std::memcpy(vac_module, module_info->module_binary_buffer, vac_module_size);

				utils::logger::info("%s \n", "new module mapping...");
				utils::logger::info("%s 0x%p\n", " module size ->", module_info->module_binary_size);
				utils::logger::info("%s 0x%p\n", " module address ->", module_info->module_binary_buffer);
			}

			/*
				execute original function to get module base
			*/

			void* result = oVacModuleExecute(th, a2);

			utils::logger::info("%s 0x%p\n", " module mapped at ->", module_info->m_pModule->ModuleBase);

			/*
				if new module loaded, write dump to disk
			*/

			if (vac_module && vac_module_size) {
				std::string module_path = "C:/vac/vac_0x";
				module_path += utils::math::int_to_hexstring(reinterpret_cast<int>(module_info->m_pModule->ModuleBase));
				module_path += ".bin";

				if (utils::file::write_binary(vac_module, vac_module_size, module_path.c_str())) {
					utils::logger::info("%s \n", " module dumped");
				}
				else {
					utils::logger::warn("%s \n", " module dump fail");
				}
			}
			
			/*
				write packet dump
			*/

			std::string packet_path = "C:/vac/vacpacket_0x";
			packet_path += utils::math::int_to_hexstring(reinterpret_cast<int>(module_info->m_pModule->ModuleBase));
			packet_path += "_";
			packet_path += std::to_string(utils::math::randint());
			packet_path += ".bin";

			if (utils::file::write_binary(packet, packet_size, packet_path.c_str())) {
				utils::logger::info("%s \n", " packet dumped");
			}
			else {
				utils::logger::warn("%s \n", " packet dump fail");
			}

			// clear some memory stuff

			delete[] packet;

			if (vac_module) {
				delete[] vac_module;
			}
			
			return result;
		}
	}

	void init() {
		// logger init
		utils::logger::init();

		utils::logger::info("%s \n", "Hello vac dumper ^:)");

		/*
			creating directory for dumps
		*/

		if (!utils::file::dir::directory_exist("C:/vac")) {
			if (utils::file::dir::directory_create("C:/vac")) {
				utils::logger::info("%s \n", "directory for dumps created");
			}
			else {
				utils::logger::fatal("%s \n", "create directory for dumps failed");
				return;
			}
		}

		/*
			waiting steamservice module
		*/

		void* steamservice = nullptr;

		utils::logger::info("%s \n", "Waiting steamservice module");

		do
		{
			steamservice = GetModuleHandleA("steamservice.dll");
		} while (steamservice == nullptr);

		utils::logger::info("%s 0x%p\n", "steamservice.dll ->", steamservice);

		/*
			find vac execution functions
		*/

		void* VacModuleExecute = utils::mem::find_signature(steamservice, "53 56 8B F1 57 8B BE");

		if (VacModuleExecute == nullptr) {
			utils::logger::fatal("%s \n", "VacModuleExecute function find fail, maybe pattern outdated");
			return;
		}

		utils::logger::info("%s 0x%p \n", "VacModuleExecute ->", VacModuleExecute);

		hooked::find_vac_module_info_index = reinterpret_cast<hooked::find_vac_module_info_index_t>(utils::mem::find_signature(steamservice, "55 8B EC 8B 41 ? 83 F8 FF"));

		if (hooked::find_vac_module_info_index == nullptr) {
			utils::logger::fatal("%s \n", "find_vac_module_info_index function find fail, maybe pattern outdated");
			return;
		}

		utils::logger::info("%s 0x%p \n", "find_vac_module_info_index ->", hooked::find_vac_module_info_index);

		/*
			init hooks
		*/

		if (MH_Initialize() != MH_OK) {
			utils::logger::fatal("%s\n", "Minhook init fail");
			return;
		}
		else {
			utils::logger::info("%s\n", "Minhook initializated");
		}

		if (MH_CreateHook(VacModuleExecute, hooked::hVacModuleExecute, reinterpret_cast<void**>(&hooked::oVacModuleExecute)) != MH_OK) {
			utils::logger::fatal("%s\n", "VacModuleExecute create hook fail");
		}
		else {
			utils::logger::info("%s\n", "VacModuleExecute hook created");
		}

		if (MH_EnableHook(VacModuleExecute) != MH_OK) {
			utils::logger::fatal("%s\n", "VacModuleExecute enable hook fail");
		}
		else {
			utils::logger::info("%s\n", "VacModuleExecute hook enabled");
		}

		utils::logger::info("%s\n", "Vac dumper sucessfully initializated, please start any vac protected game");
	}
}