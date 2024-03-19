#pragma once

// Baseadresse til modulen (exe filen) som vi er i.
uintptr_t BaseAddr = (uintptr_t)GetModuleHandle(NULL);

// Adresse til helseverdi, hentet fra IDA.
uintptr_t HealthAddr = (BaseAddr + 0x3C5C0);