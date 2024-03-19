#pragma once

/*
	Hektefunksjoner brukes for å sette inn et assembly hopp i starten 
	av importert funksjon i målprosess for å hoppe til vår egen. 

	Når det er gjort kan vi hekte av/på og overstyre operasjoner.

	Denne filen prøver å ta hensyn til 32/64 bit variasjoner.
	Juster _64BitHook parameteren i hektefunksjonene etter behov.
 */

// Orginale bytes. Bruk respektive 32/64 bit versjoner, 
// i overstyringsfunksjoner som er under hektefunksjoner.
unsigned char H_MessageBoxA32[6];
unsigned char H_MessageBoxA64[14];

//
//	HEKTEFUNKSJONER.
//
bool HektFunksjon(
	const char* pModule,
	const char* pOrigFunc,
	void* pOverrideFunc,
	unsigned char* pBackup,
	bool _64BitHook
){
	// Variabler.
	DWORD OrigVProtFlags;

	// Foretrekker FF 25 for 64-bit bruk.
	unsigned char jmp64[14] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	
	// Foretrekker E9 C3 for 32-bit bruk.
	unsigned char jmp32[6] = {
		0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3
	};

	// Hent opprinnelig addr til funksjon vi hekter.
	uintptr_t OrigFuncAddr = (uintptr_t)GetProcAddress(
		GetModuleHandleA(pModule), 
		pOrigFunc
	);
	//wchar_t dbgbuf[100];
	//swprintf(dbgbuf, 100, L"\nDEBUG OrigFuncAddr funnet ved hekting: 0x%llx\n\n", (DWORD64)OrigFuncAddr);
	//wprintf(dbgbuf);
	
	// Ta kopi av hva enn bytes som finnes,
	// der vi skal hoppe til egen funksjon.
	if (ReadProcessMemory(
		GetCurrentProcess(), 
		(void*)OrigFuncAddr,
		pBackup,
		(_64BitHook?14:6),
		0
	) == 0)
		return false;

	// Minnet er ikke allokert av oss.
	// Prøv å få skriverettighet til minne.
	if (VirtualProtect(
		(void*)OrigFuncAddr, 
		(_64BitHook?14:6), 
		PAGE_EXECUTE_READWRITE, 
		&OrigVProtFlags
	) == 0)
		return false;

	// Beregn hopp til overstyrende funksjon.
	if (_64BitHook)
		*(DWORD64*)&jmp64[6] = (DWORD64)pOverrideFunc;
	else
		*(DWORD*)&jmp32[1] = (DWORD)((DWORD)pOverrideFunc - OrigFuncAddr - 5);

	// Skriv hopp til starten av opprinnelig funksjon.
	if (WriteProcessMemory(
		GetCurrentProcess(),
		(void*)OrigFuncAddr,
		(_64BitHook?jmp64:jmp32),
		(_64BitHook?14:6),
		0
	) == 0)
		return false;

	// Sett opprinnelig minnebeskyttelse.
	if (VirtualProtect(
		(void*)OrigFuncAddr, 
		(_64BitHook?14:6), 
		OrigVProtFlags, 
		&OrigVProtFlags
	) == 0)
		return false;

	// Sørg for at CPU bruker nye endringer.
	FlushInstructionCache(GetCurrentProcess(),0,0);
	return true;
}

bool AvHektFunksjon(
	const char* pModule,
	const char* pOrigFunc,
	unsigned char* pBackup,
	bool _64BitHook
){
	DWORD OrigVProtFlags;

	// Hent opprinnelige addr til funksjon vi hekter.
	uintptr_t OrigFuncAddr = (uintptr_t)GetProcAddress(
		GetModuleHandleA(pModule), 
		pOrigFunc
	);

	// Minnet er ikke allokert av oss.
	// Prøv å få skriverettighet til minne.
	if (VirtualProtect(
		(void*)OrigFuncAddr, 
		(_64BitHook?14:6), 
		PAGE_EXECUTE_READWRITE, 
		&OrigVProtFlags
	) == 0)
		return false;

	if (WriteProcessMemory(
		GetCurrentProcess(),
		(void*)OrigFuncAddr,
		pBackup,
		(_64BitHook?14:6),
		0
	) == 0)
		return false;

	// Sett opprinnelig minnebeskyttelse.
	if (VirtualProtect(
		(void*)OrigFuncAddr, 
		(_64BitHook?14:6), 
		OrigVProtFlags, 
		&OrigVProtFlags
	) == 0)
		return false;

	// Sørg for at CPU bruker nye endringer.
	FlushInstructionCache(GetCurrentProcess(),0,0);
	return true;
}

// Overstyringsfunksjoner.
int my_MessageBoxA(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
) {
	// Hekt av for å la normal operasjon fullføre.
	if (!AvHektFunksjon(
		"user32.dll", 
		"MessageBoxA",
		H_MessageBoxA64,
		true
	)) { return 0; }

	// Normal operasjon.
	MessageBoxA(hWnd,lpText,lpCaption,uType);

	// Egen operasjon/overstyring.
	wprintf(L"Jeg hektet meg inn i meldingsboksene dine! ~Thronic~\n");

	// Hekt funksjon igjen for å fange opp videre kall.
	if (!HektFunksjon(
		"user32.dll", 
		"MessageBoxA", 
		(void**)my_MessageBoxA, 
		H_MessageBoxA64,
		true
	)) { return 0; } 
	
	Log("Overstyrte 'MessageBoxA'.");
	return 0;
}