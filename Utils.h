#pragma once

// make sure to get thedoomed's eyestep
#include "memedit.hpp"
#include "memscan.hpp"
#include "routine_mgr.hpp"

#include <Windows.h>
#include <iostream>

using namespace std;

/*
	This function fix aslr plus add on 0x4000 as the disassembler is typically off by
	that exact amount on every address
*/
uint32_t aslr(uint32_t address)
{
	return (address - reinterpret_cast<uint32_t>(disassembler::base_module)) + 0x400000 + 0x4000;
}

double AddressCount = 0;

/*
	This function prints addresses to the console with the callinv conv
*/
void PrintAddress(string Name, uintptr_t Address)
{
	AddressCount++;
	cout << Name << ": " << "0x" << std::hex << aslr(Address) << " " << str_conv(routine_mgr::get_conv(Address, get_arg_count(Address))) << endl;
}

/*
	This function can get a address that contains a string and the xref of it so if their are multiple you
	can get a different one
*/
uintptr_t GetCallingFunctionFromString(const char* string, int xref)
{
	auto functions_scan = new scanner::memscan();
	functions_scan->scan_xrefs(string, xref);
	auto results = functions_scan->get_results();
	auto first_xref = results.front();
	auto address = get_prologue<behind>(first_xref);
	delete functions_scan;
	return address;
}

/*
	This function gets a specific xref from an address
*/
uintptr_t GetXref(uintptr_t Address, int xref)
{
	auto xref_scan = new scanner::memscan();
	xref_scan->scan_xrefs(Address);
	auto results = xref_scan->get_results();
	auto xrefn = results[xref];
	auto address = get_prologue<behind>(xrefn);
	delete xref_scan;
	return address;
}

/*
	This function gets all xrefs of an address
*/
std::vector<uintptr_t> GetXrefs(uintptr_t Address)
{
	auto xref_scan = new scanner::memscan();
	xref_scan->scan_xrefs(Address);
	auto results = xref_scan->get_results();

	std::vector<uintptr_t> Final = {};

	for (auto i : results)
	{
		Final.push_back(get_prologue<behind>(i));
	}
	return Final;
}

/*
	Checks if a string is present inside a address
*/
bool IsStringPresent(uintptr_t Address, const char *string)
{
	auto functions_scan = new scanner::memscan();
	functions_scan->scan_xrefs(string, 0);
	auto results = functions_scan->get_results();

	if (results.size() != 0) { return true; } 
	else { return false; }
}
