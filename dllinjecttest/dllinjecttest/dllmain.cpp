#include "main.h"

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			
			//
			//	Starter en tråd med oppgave-loop.
			//	Gå til main.h for å lage oppsett.
			//
			//	Mal kommer med eksempler for hacking av 
			//	Dummy1ForIda.exe - Testet OK i Des 2019.
			//	
			//	Numpad5 = typedef internt funksjonskall.
			//	Numpad6 = Direkte internt funksjonskall.
			//	Numpad8 = Skrive verdier til minne.
			//	Numpad9 = Hekte interne funksjoner.
			//

			CloseHandle(
				CreateThread(
					nullptr, 
					0, 
					(LPTHREAD_START_ROUTINE)SpillKjeks, 
					hModule, 
					0, 
					nullptr)
				);
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

    return TRUE;
}
