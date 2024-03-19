#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include "Adresser.h"
#include "Logging.h"
#include "Hektefunksjoner.h"

struct NumpadKeys {
	bool Active = false;
	bool IsDown = false;
} Numpad1, Numpad2, Numpad3, Numpad4;

// Typedefinisjoner. Eksplisitt kall-konvensjon er ikke nødvendigvis et must.
// Typer hentes fra f.eks. IDA, x64dbg o.l. hvor man gjør reversering.
typedef __int64 (__fastcall *CallInternalFunc1T)(__int64);
CallInternalFunc1T CallInternalFunc1 = (CallInternalFunc1T)(BaseAddr + 0x1100);

/* Eksempel på en mer direkte måte å kalle interne funksjoner på.
int IngameFunctionFoo()
{
	1. Lag en peker til funksjonstype:
	void(*)(int)
	2. Kast returverdien til den (int):
	(void(*)(int))0xDEADBEEF
	3. Kall funksjonen med parametere:
	((void(*)(int))0xDEADBEEF)(123)

	return ((int(*)(Paramtype1,Paramtype2))(BaseAddr + 0x4B20))(
		Parameterverdi1, Parameterverdi2
	);

	I main loop:
	if (GetAsyncKeyState(VK_NUMPAD6) & 1)
		IngameFunctionFoo();
}*/

DWORD __stdcall SpillKjeks(HMODULE hModule)
{
	// Sett opp arbeid som skal gjøres internt i spillet.
	while (true) {

		// Numpad1 (kalle wprintf)
		if ((GetAsyncKeyState(VK_NUMPAD1) & 0x8000) && !Numpad1.IsDown) {
			Numpad1.IsDown = true;

			if (!Numpad1.Active) {
				const wchar_t* HackString = L"\nWake up NEO!\nFollow the white rabbit!\n~Thronic~\n\n";

				// Typisk måte med typedef å kalle interne funksjoner.
				// I dette tilfellet wprintf(const wchar_t*).
				CallInternalFunc1((__int64)HackString);

				//Numpad5Active = true;
				Log("Aktivert Numpad1.");
			}

		} else if (!(GetAsyncKeyState(VK_NUMPAD1) & 0x8000)) {
			Numpad1.IsDown = false;
		}



		// Numpad2 (kalle msg box)
		if ((GetAsyncKeyState(VK_NUMPAD2) & 0x8000) && !Numpad2.IsDown) {
			Numpad2.IsDown = true;

			if (!Numpad2.Active) {
				const char* HackString = "\nWake up NEO!\nFollow the white rabbit!\n~Thronic~\n\n";

				// Eksempel på en mer direkte måte å kalle interne funksjoner.
				// I dette tilfellet tilkaller vi MessageBoxA i målprosessen.

				// Hent opprinnelige addr siden den er importert til målprosessen.
				uintptr_t ImportedFuncAddr = (uintptr_t)GetProcAddress(
					GetModuleHandle(L"user32.dll"), 
					"MessageBoxA"
				);

				((int(__stdcall*)(HWND,LPCSTR,LPCSTR,UINT))ImportedFuncAddr)(
					0,
					HackString,
					"",
					0
				);

				//Numpad2Active = true;
				Log("Aktivert Numpad2.");
			}

		} else if (!(GetAsyncKeyState(VK_NUMPAD2) & 0x8000)) {
			Numpad2.IsDown = false;
		}



		// Numpad3 (forandre variabelverdier).
		if ((GetAsyncKeyState(VK_NUMPAD3) & 0x8000) && !Numpad3.IsDown) {
			Numpad3.IsDown = true;

			if (!Numpad3.Active) {
				
				/*
				// Når vi er internt i målprosess slipper vi RPM/WPM pes.
				// Vi kan skrive direkte der vi vil, når vi vil. >.>
				// Men lurt å huske å "låse opp" området før vi gjør det.
				// Samt låse igjen etter oss, med VirtualProtect(). 
				// På minne vi selv allokerer trenger vi den ikke, f.eks.:

				uintptr_t memPageStep = 0;
				while ((CaveAddr = (uintptr_t)VirtualAlloc(
					(void*)(TargetPtr + memPageStep),
					1000,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_EXECUTE_READWRITE
				)) == NULL)
					memPageStep += 1000;

				// Siden vi allerede setter READWRITE rettigheter. Men på 
				// spillets eget minne må vi huske å ta hensyn til dette.
				*/

				DWORD oldprotect;
				VirtualProtect((void*)HealthAddr, sizeof(float), PAGE_EXECUTE_READWRITE, &oldprotect);
				*(float*)(HealthAddr) = 999.0f;
				VirtualProtect((void*)HealthAddr, sizeof(float), oldprotect, &oldprotect);

				// Rapporter ny helseverdi.
				float OppdatertHelse = *(float*)HealthAddr;
				wchar_t buf[100];
				swprintf(buf, 100, L"\nHacket helse, ny verdi: %.0f, mvh ~Thronic~\n\n", OppdatertHelse);
				CallInternalFunc1((__int64)buf);
				
				//Numpad8Active = true;
				Log("Aktivert Numpad3.");
			}

		} else if (!(GetAsyncKeyState(VK_NUMPAD3) & 0x8000)) {
			Numpad3.IsDown = false;
		}



		// Numpad4 (hekte msg box).
		if ((GetAsyncKeyState(VK_NUMPAD4) & 0x8000) && !Numpad4.IsDown) {
			Numpad4.IsDown = true;

			if (!Numpad4.Active) {
				
				// Hekt MessageBoxA for illustrering av overstyring av funksjoner.
				HektFunksjon(
					"user32.dll",
					"MessageBoxA",
					(void**)my_MessageBoxA,
					H_MessageBoxA64,
					true					
				);
				
				//Numpad4Active = true;
				Log("Aktivert Numpad4.");
			}

		} else if (!(GetAsyncKeyState(VK_NUMPAD4) & 0x8000)) {
			Numpad4.IsDown = false;
		}
	}

	// Frigjør og avslutt injisert tråd.
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}