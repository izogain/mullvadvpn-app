#include "stdafx.h"
#include <libcommon/string.h>
#include "windns.h"
#include "confineoperation.h"
#include "netsh.h"
#include "logsink.h"
#include <memory>
#include <vector>
#include <string>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <winsock2.h>	//
#include <iphlpapi.h>	// magic order :-(
						// if we don't do this then most of iphlpapi is not actually defined

// TODO: This file will move location on disk.
#include "adapters.h"

bool operator==(const IN_ADDR &lhs, const IN_ADDR &rhs)
{
	return 0 == memcmp(&lhs, &rhs, sizeof(IN_ADDR));
}

bool operator==(const IN6_ADDR &lhs, const IN6_ADDR &rhs)
{
	return 0 == memcmp(&lhs, &rhs, sizeof(IN6_ADDR));
}

namespace
{

std::shared_ptr<LogSink> g_LogSink;
std::shared_ptr<NetSh> g_NetSh;

std::vector<std::wstring> MakeStringArray(const wchar_t **strings, uint32_t numStrings)
{
	std::vector<std::wstring> v;

	while (numStrings--)
	{
		v.emplace_back(*strings++);
	}

	return v;
}

void ForwardError(const char *message, const char **details, uint32_t numDetails)
{
	if (nullptr != g_LogSink)
	{
		g_LogSink->error(message, details, numDetails);
	}
}

uint32_t ConvertInterfaceAliasToIndex(const std::wstring &interfaceAlias)
{
	NET_LUID luid;

	if (NO_ERROR != ConvertInterfaceAliasToLuid(interfaceAlias.c_str(), &luid))
	{
		const auto err = std::wstring(L"Could not resolve LUID of interface: \"")
			.append(interfaceAlias).append(L"\"");

		throw std::runtime_error(common::string::ToAnsi(err).c_str());
	}

	NET_IFINDEX index;

	if (NO_ERROR != ConvertInterfaceLuidToIndex(&luid, &index))
	{
		std::wstringstream ss;

		ss << L"Could not resolve index of interface: \"" << interfaceAlias << L"\""
			<< L"with LUID: 0x" << std::hex << luid.Value;

		throw std::runtime_error(common::string::ToAnsi(ss.str()).c_str());
	}

	return static_cast<uint32_t>(index);
}

struct AdapterDnsAddresses
{
	std::vector<IN_ADDR> ipv4;
	std::vector<IN6_ADDR> ipv6;
};

//
// Use name when finding the adapter to be more resilient over time.
// The adapter structure that is returned has two fields for interface index.
// If IPv4 is enabled, 'IfIndex' will be set. Otherwise set to 0.
// If IPv6 is enabled, 'Ipv6IfIndex' will be set. Otherwise set to 0.
// If both IPv4 and IPv6 is enabled, then both fields will be set, and have the same value.
//
AdapterDnsAddresses GetAdapterDnsAddresses(const std::wstring &adapterAlias)
{
	Adapters adapters(AF_UNSPEC, GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST);

	const IP_ADAPTER_ADDRESSES *adapter;

	while (nullptr != (adapter = adapters.next()))
	{
		if (0 != _wcsicmp(adapter->FriendlyName, adapterAlias.c_str()))
		{
			continue;
		}

		AdapterDnsAddresses out;

		for (auto server = adapter->FirstDnsServerAddress; nullptr != server; server = server->Next)
		{
			if (AF_INET == server->Address.lpSockaddr->sa_family)
			{
				out.ipv4.push_back(((const SOCKADDR_IN*)server->Address.lpSockaddr)->sin_addr);
			}
			else if (AF_INET6 == server->Address.lpSockaddr->sa_family)
			{
				out.ipv6.push_back(((const SOCKADDR_IN6_LH*)server->Address.lpSockaddr)->sin6_addr);
			}
		}

		return out;
	}

	throw std::runtime_error(std::string("Could not find interface: ")
		.append(common::string::ToAnsi(adapterAlias)).c_str());
}

AdapterDnsAddresses ConvertAddresses(
	const wchar_t **ipv4Servers,
	uint32_t numIpv4Servers,
	const wchar_t **ipv6Servers,
	uint32_t numIpv6Servers
)
{
	AdapterDnsAddresses out;

	if (nullptr != ipv4Servers && 0 != numIpv4Servers)
	{
		for (uint32_t i = 0; i < numIpv4Servers; ++i)
		{
			IN_ADDR converted;

			if (1 != InetPtonW(AF_INET, ipv4Servers[i], &converted))
			{
				throw std::runtime_error("Failed to convert IPv4 address");
			}

			out.ipv4.push_back(converted);
		}
	}

	if (nullptr != ipv6Servers && 0 != numIpv6Servers)
	{
		for (uint32_t i = 0; i < numIpv6Servers; ++i)
		{
			IN6_ADDR converted;

			if (1 != InetPtonW(AF_INET6, ipv6Servers[i], &converted))
			{
				throw std::runtime_error("Failed to convert IPv6 address");
			}

			out.ipv6.push_back(converted);
		}
	}

	return out;
}

bool Equal(const AdapterDnsAddresses &lhs, const AdapterDnsAddresses &rhs)
{
	return lhs.ipv4 == rhs.ipv4
		&& lhs.ipv6 == rhs.ipv6;
}

} // anonymous namespace

WINDNS_LINKAGE
bool
WINDNS_API
WinDns_Initialize(
	WinDnsLogSink logSink,
	void *logContext
)
{
	if (g_LogSink)
	{
		return false;
	}

	return ConfineOperation("Initialize", ForwardError, [&]()
	{
		g_LogSink = std::make_shared<LogSink>(LogSinkInfo{ logSink, logContext });

		try
		{
			g_NetSh = std::make_shared<NetSh>(g_LogSink);
		}
		catch (...)
		{
			g_LogSink.reset();
			throw;
		}
	});
}

WINDNS_LINKAGE
bool
WINDNS_API
WinDns_Deinitialize(
)
{
	g_NetSh.reset();
	g_LogSink.reset();

	return true;
}

WINDNS_LINKAGE
bool
WINDNS_API
WinDns_Set(
	const wchar_t *interfaceAlias,
	const wchar_t **ipv4Servers,
	uint32_t numIpv4Servers,
	const wchar_t **ipv6Servers,
	uint32_t numIpv6Servers
)
{
	return ConfineOperation("Apply DNS settings", ForwardError, [&]()
	{
		//
		// Check the settings on the adapter.
		// If it already has the exact same settings we need, we're done.
		//

		try
		{
			const auto activeSettings = GetAdapterDnsAddresses(interfaceAlias);
			const auto wantedSetting = ConvertAddresses(ipv4Servers, numIpv4Servers, ipv6Servers, numIpv6Servers);

			if (Equal(activeSettings, wantedSetting))
			{
				g_LogSink->info("DNS settings on adapter are up-to-date", nullptr, 0);
				return;
			}
		}
		catch (...)
		{
			g_LogSink->error("Failed to evaluate existing DNS settings on adapter", nullptr, 0);
		}

		//
		// Onwards
		//

		const auto interfaceIndex = ConvertInterfaceAliasToIndex(interfaceAlias);

		if (nullptr != ipv4Servers && 0 != numIpv4Servers)
		{
			g_NetSh->setIpv4StaticDns(interfaceIndex, MakeStringArray(ipv4Servers, numIpv4Servers));
		}
		else
		{
			// This is required to clear any current settings.
			g_NetSh->setIpv4DhcpDns(interfaceIndex);
		}

		if (nullptr != ipv6Servers && 0 != numIpv6Servers)
		{
			g_NetSh->setIpv6StaticDns(interfaceIndex, MakeStringArray(ipv6Servers, numIpv6Servers));
		}
		else
		{
			// This is required to clear any current settings.
			g_NetSh->setIpv6DhcpDns(interfaceIndex);
		}
	});
}
