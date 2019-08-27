#include "stdafx.h"
#include "adapters.h"
#include "libcommon/error.h"

const IP_ADAPTER_ADDRESSES *Adapters::next() const
{
	if (nullptr == m_currentEntry)
	{
		return nullptr;
	}

	auto entry = m_currentEntry;
	m_currentEntry = m_currentEntry->Next;

	return entry;
}

Adapters::Adapters(DWORD family, DWORD flags)
{
	std::vector<uint8_t> buffer;

	static const size_t MSDN_RECOMMENDED_STARTING_BUFFER_SIZE = 1024 * 15;
	buffer.resize(MSDN_RECOMMENDED_STARTING_BUFFER_SIZE);

	ULONG bufferSize = static_cast<ULONG>(buffer.size());
	auto bufferPointer = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(&buffer[0]);

	//
	// Acquire interfaces.
	//

	for (;;)
	{
		const auto status = GetAdaptersAddresses(family, flags, nullptr, bufferPointer, &bufferSize);

		if (ERROR_SUCCESS == status)
		{
			break;
		}

		THROW_UNLESS(ERROR_BUFFER_OVERFLOW, status, "Probe required buffer size for GetAdaptersAddresses");

		buffer.resize(bufferSize);
		bufferPointer = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(&buffer[0]);
	}

	m_buffer = std::move(buffer);
	reset();
}
