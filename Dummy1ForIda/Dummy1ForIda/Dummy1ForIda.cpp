#include "pch.h"
#include <Windows.h>
#include <iostream>

// Default health value.
float Health = 100.0f;

bool HealthIsFull(float* h)
{
	if (*h >= 100.0f)
		return true;
	else
		return false;
}

void ReportReadyForHacking()
{
	MessageBoxA(0,"Program ready!","",0);
}

int main()
{
	if (SetConsoleOutputCP(65001) != 0)
		std::wcout << "Setting UTF8 output code page (65001).\n\n";
	else if (SetConsoleOutputCP(28591) != 0)
		std::wcout << "UTF8 unavailable, using no-latin1 (28591)\n\n";
	else
		std::wcout << "FFS. Can't set a proper code page. Using default. Good luck!\n\n";

	// Initiell print data.
	std::wcout << "Hello World!\n\n";
	ReportReadyForHacking();

	while (true) {

		// Venter på at noen skal hacke oss.
		if (GetAsyncKeyState(VK_SPACE) & 0x0001) {
			wprintf(L"Venter på at noen skal hacke oss\n");
		
			// Oppdater helse.
			std::wcout << "Health: " << Health << std::endl;
			std::wcout << "Health Full? " << (HealthIsFull(&Health) == true ? "YES!" : "NO!") << std::endl << std::endl;
		}

		Sleep(10);
	}

	return 0;
}

