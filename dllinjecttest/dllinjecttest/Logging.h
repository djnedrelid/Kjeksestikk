#pragma once

// Lagre logg direkte i målmappen.
const char* LogFile = "SpillKjeks.log";

// Loggefunksjon for problemløsning.
void Log(const char* s)
{
	// Klargjør melding- og tidvariabler.
	std::ofstream f;
	std::time_t t = std::time(nullptr);
	std::string asctime = std::asctime(std::localtime(&t));
	asctime.pop_back();

	// Åpne loggfil i appending-modus, skriv og lukk.
	f.open(LogFile, std::fstream::app);
	f << std::endl;
	f << asctime.c_str() << ": " << s << std::endl;
	f.close();

	/*
		Kode hvis behov for mer avansert logging med miksede typer.
		
		std::stringstream LogStr;
		LogStr << std::endl;
		LogStr << "Hekter av '" << pOrigFunc << " for skreddersydd bruk...";
		Log(LogStr.str().c_str());
	 */
}