#include "stdafx.h"
#include "routemanager.h"
#include "adapters.h"
#include <libcommon/error.h>
#include <libcommon/memory.h>
#include <libcommon/string.h>
#include <libcommon/synchronization.h>
#include <vector>
#include <algorithm>
#include <numeric>
#include <sstream>

using LockType = common::sync::ScopeLock<std::recursive_mutex>;

namespace
{

bool GetAdapterInterface(NET_LUID adapter, ADDRESS_FAMILY addressFamily, MIB_IPINTERFACE_ROW *iface)
{
	memset(iface, 0, sizeof(MIB_IPINTERFACE_ROW));

	iface->Family = addressFamily;
	iface->InterfaceLuid = adapter;

	return NO_ERROR == GetIpInterfaceEntry(iface);
}

struct AnnotatedRoute
{
	const MIB_IPFORWARD_ROW2 *route;
	bool active;
	uint32_t effectiveMetric;
};

template<typename T>
bool bool_cast(const T &value)
{
	return 0 != value;
}

std::vector<AnnotatedRoute> AnnotateRoutes(const std::vector<const MIB_IPFORWARD_ROW2 *> &routes)
{
	std::vector<AnnotatedRoute> annotated;
	annotated.reserve(routes.size());

	for (auto route : routes)
	{
		MIB_IPINTERFACE_ROW iface;

		if (false == GetAdapterInterface(route->InterfaceLuid, route->DestinationPrefix.Prefix.si_family, &iface))
		{
			continue;
		}

		annotated.emplace_back
		(
			AnnotatedRoute{ route, bool_cast(iface.Connected), route->Metric + iface.Metric }
		);
	}

	return annotated;
}

bool RouteHasGateway(const MIB_IPFORWARD_ROW2 &route)
{
	switch (route.NextHop.si_family)
	{
		case AF_INET:
		{
			return 0 != route.NextHop.Ipv4.sin_addr.s_addr;
		}
		case AF_INET6:
		{
			const uint8_t *begin = &route.NextHop.Ipv6.sin6_addr.u.Byte[0];
			const uint8_t *end = begin + 16;

			return 0 != std::accumulate(begin, end, 0);
		}
		default:
		{
			return false;
		}
	};
}

struct InterfaceAndGateway
{
	NET_LUID iface;
	routemanager::NodeAddress gateway;
};

InterfaceAndGateway ResolveNodeFromDefaultRoute(ADDRESS_FAMILY family)
{
	PMIB_IPFORWARD_TABLE2 table;

	auto status = GetIpForwardTable2(family, &table);

	THROW_UNLESS(NO_ERROR, status, "Acquire route table");

	common::memory::ScopeDestructor sd;

	sd += [table]
	{
		FreeMibTable(table);
	};

	std::vector<const MIB_IPFORWARD_ROW2 *> candidates;
	candidates.reserve(table->NumEntries);

	//
	// Enumerate routes looking for: route 0/0 && gateway specified.
	//

	for (ULONG i = 0; i < table->NumEntries; ++i)
	{
		const MIB_IPFORWARD_ROW2 &candidate = table->Table[i];

		if (0 == candidate.DestinationPrefix.PrefixLength
			&& RouteHasGateway(candidate))
		{
			candidates.emplace_back(&candidate);
		}
	}

	auto annotated = AnnotateRoutes(candidates);

	if (annotated.empty())
	{
		throw std::runtime_error("Unable to determine details of default route");
	}

	//
	// Sort on (active, effectiveMetric) ascending by metric.
	//

	std::sort(annotated.begin(), annotated.end(), [](const AnnotatedRoute &lhs, const AnnotatedRoute &rhs)
	{
		if (lhs.active == rhs.active)
		{
			return lhs.effectiveMetric < rhs.effectiveMetric;
		}

		return lhs.active && false == rhs.active;
	});

	//
	// Ensure the top rated route is active.
	//

	if (false == annotated[0].active)
	{
		throw std::runtime_error("Unable to identify active default route");
	}

	return InterfaceAndGateway { annotated[0].route->InterfaceLuid, annotated[0].route->NextHop };
}

bool AdapterInterfaceEnabled(const IP_ADAPTER_ADDRESSES *adapter, ADDRESS_FAMILY family)
{
	switch (family)
	{
		case AF_INET:
		{
			return 0 != adapter->Ipv4Enabled;
		}
		case AF_INET6:
		{
			return 0 != adapter->Ipv6Enabled;
		}
		default:
		{
			throw std::runtime_error("Missing case handler in switch clause");
		}
	}
}

std::vector<const SOCKET_ADDRESS *> IsolateGatewayAddresses(
	PIP_ADAPTER_GATEWAY_ADDRESS_LH head, ADDRESS_FAMILY family)
{
	std::vector<const SOCKET_ADDRESS *> matches;

	for (auto gateway = head; nullptr != gateway; gateway = gateway->Next)
	{
		if (family == gateway->Address.lpSockaddr->sa_family)
		{
			matches.emplace_back(&gateway->Address);
		}
	}

	return matches;
}

bool EqualAddress(const SOCKADDR_INET *lhs, const SOCKET_ADDRESS *rhs)
{
	if (lhs->si_family != rhs->lpSockaddr->sa_family)
	{
		return false;
	}

	switch (lhs->si_family)
	{
		case AF_INET:
		{
			auto typedRhs = reinterpret_cast<const SOCKADDR_IN *>(rhs->lpSockaddr);
			return lhs->Ipv4.sin_addr.s_addr == typedRhs->sin_addr.s_addr;
		}
		case AF_INET6:
		{
			auto typedRhs = reinterpret_cast<const SOCKADDR_IN6 *>(rhs->lpSockaddr);
			return 0 == memcmp(lhs->Ipv6.sin6_addr.u.Byte, typedRhs->sin6_addr.u.Byte, 16);
		}
		default:
		{
			throw std::runtime_error("Missing case handler in switch clause");
		}
	}
}

bool AddressPresent(const std::vector<const SOCKET_ADDRESS *> &hay, const SOCKADDR_INET *needle)
{
	for (const auto candidate : hay)
	{
		if (EqualAddress(needle, candidate))
		{
			return true;
		}
	}

	return false;
}

NET_LUID InterfaceLuidFromGateway(const routemanager::NodeAddress &gateway)
{
	const DWORD adapterFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
		| GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_INCLUDE_GATEWAYS;

	Adapters adapters(gateway.si_family, adapterFlags);

	//
	// Process adapters to find matching ones.
	//

	std::vector<const IP_ADAPTER_ADDRESSES *> matches;

	for (auto adapter = adapters.next(); nullptr != adapter; adapter = adapters.next())
	{
		if (false == AdapterInterfaceEnabled(adapter, gateway.si_family))
		{
			continue;
		}

		auto gateways = IsolateGatewayAddresses(adapter->FirstGatewayAddress, gateway.si_family);

		if (AddressPresent(gateways, &gateway))
		{
			matches.emplace_back(adapter);
		}
	}

	if (matches.empty())
	{
		throw std::runtime_error("Unable to find network adapter with specified gateway");
	}

	//
	// Sort matching interfaces ascending by metric.
	//

	const bool targetV4 = (AF_INET == gateway.si_family);

	std::sort(matches.begin(), matches.end(), [&targetV4](const IP_ADAPTER_ADDRESSES *lhs, const IP_ADAPTER_ADDRESSES *rhs)
	{
		if (targetV4)
		{
			return lhs->Ipv4Metric < rhs->Ipv4Metric;
		}

		return lhs->Ipv6Metric < rhs->Ipv6Metric;
	});

	//
	// Select the interface with the best (lowest) metric.
	//

	return matches[0]->Luid;
}

InterfaceAndGateway ResolveNode(ADDRESS_FAMILY family, const std::optional<routemanager::Node> &optionalNode)
{
	//
	// There are four cases:
	//
	// Unspecified node (use interface and gateway of default route).
	// Node is specified by name.
	// Node is specified by name and gateway.
	// Node is specified by gateway.
	//

	if (false == optionalNode.has_value())
	{
		return ResolveNodeFromDefaultRoute(family);
	}

	const auto &node = optionalNode.value();

	if (node.deviceName().has_value())
	{
		const auto &deviceName = node.deviceName().value();
		NET_LUID luid;

		//
		// Try to parse a string encoded LUID.
		// The `#` is a valid character in adapter names so we use `?` instead.
		// The LUID is thus prefixed with `?` and hex encoded and left-padded with zeroes
		// E.g. `?deadbeefcafebabe` or `?000dbeefcafebabe`
		//

		static const size_t StringEncodedLuidLength = 17;

		if (StringEncodedLuidLength == deviceName.size()
			 && L'?' == deviceName[0])
		{
			try
			{
				std::wstringstream ss;

				ss << std::hex << &deviceName[1];
				ss >> luid.Value;
			}
			catch (std::exception &)
			{
				const auto ansiName = common::string::ToAnsi(deviceName);
				const auto err = std::string("Failed to parse string encoded LUID: ").append(ansiName);

				std::throw_with_nested(std::runtime_error(err));
			}
		}
		else if (0 != ConvertInterfaceAliasToLuid(deviceName.c_str(), &luid))
		{
			const auto ansiName = common::string::ToAnsi(deviceName);
			const auto err = std::string("Unable to derive interface LUID from interface alias: ").append(ansiName);

			throw std::runtime_error(err);
		}

		auto onLinkProvider = [&family]()
		{
			routemanager::NodeAddress onLink = { 0 };
			onLink.si_family = family;

			return onLink;
		};

		return InterfaceAndGateway{ luid, node.gateway().value_or(onLinkProvider()) };
	}

	//
	// The node is specified only by gateway.
	//

	return InterfaceAndGateway{ InterfaceLuidFromGateway(node.gateway().value()), node.gateway().value() };
}

routemanager::NodeAddress ConvertSocketAddress(const SOCKET_ADDRESS *sa)
{
	routemanager::NodeAddress out = { 0 };

	switch (sa->lpSockaddr->sa_family)
	{
		case AF_INET:
		{
			out.si_family = AF_INET;
			out.Ipv4 = *reinterpret_cast<SOCKADDR_IN *>(sa->lpSockaddr);

			break;
		}
		case AF_INET6:
		{
			out.si_family = AF_INET6;
			out.Ipv6 = *reinterpret_cast<SOCKADDR_IN6 *>(sa->lpSockaddr);

			break;
		}
		default:
		{
			throw std::runtime_error("Missing case handler in switch clause");
		}
	};

	return out;
}

std::wstring FormatNetwork(const routemanager::Network &network)
{
	switch (network.Prefix.si_family)
	{
		case AF_INET:
		{
			return common::string::FormatIpv4(network.Prefix.Ipv4.sin_addr.s_addr, network.PrefixLength);
		}
		case AF_INET6:
		{
			return common::string::FormatIpv6(network.Prefix.Ipv6.sin6_addr.u.Byte, network.PrefixLength);
		}
		default:
		{
			return L"Failed to format network details";
		}
	}
}

} // anon namespace

namespace routemanager {

bool EqualAddress(const Network &lhs, const Network &rhs)
{
	if (lhs.PrefixLength != rhs.PrefixLength)
	{
		return false;
	}

	return EqualAddress(lhs.Prefix, rhs.Prefix);
}

bool EqualAddress(const NodeAddress &lhs, const NodeAddress &rhs)
{
	if (lhs.si_family != rhs.si_family)
	{
		return false;
	}

	switch (lhs.si_family)
	{
		case AF_INET:
		{
			return lhs.Ipv4.sin_addr.s_addr == rhs.Ipv4.sin_addr.s_addr;
		}
		case AF_INET6:
		{
			return 0 == memcmp(&lhs.Ipv6.sin6_addr, &rhs.Ipv6.sin6_addr, sizeof(IN6_ADDR));
		}
		default:
		{
			throw std::runtime_error("Invalid address family for network address");
		}
	}
}

RouteManager::RouteManager(std::shared_ptr<common::logging::ILogSink> logSink)
	: m_logSink(logSink)
{
	const auto status = NotifyRouteChange2(AF_UNSPEC, RouteChangeCallback, this, FALSE, &m_notificationHandle);

	THROW_UNLESS(NO_ERROR, status, "Register for route table change notifications");
}

RouteManager::~RouteManager()
{
	CancelMibChangeNotify2(m_notificationHandle);

	for (const auto &record : m_routes)
	{
		try
		{
			deleteFromRoutingTable(record.registeredRoute);
		}
		catch (std::exception &ex)
		{
			std::wstringstream ss;

			ss << L"Failed to delete route as part of cleaning up, Route: "
				<< FormatRegisteredRoute(record.registeredRoute);

			m_logSink->error(common::string::ToAnsi(ss.str()).c_str());
			m_logSink->error(ex.what());
		}
	}
}

void RouteManager::addRoutes(const std::vector<Route> &routes)
{
	LockType lock(m_routesLock);

	std::vector<EventEntry> eventLog;

	for (const auto &route : routes)
	{
		try
		{
			auto existing = findRoute(route);

			if (existing != m_routes.end())
			{
				deleteFromRoutingTable(existing->registeredRoute);
				eventLog.emplace_back(EventEntry{ EventType::DELETE_ROUTE, *existing });
				m_routes.erase(existing);
			}

			const RouteRecord newRecord { route, addIntoRoutingTable(route) };

			eventLog.emplace_back(EventEntry{ EventType::ADD_ROUTE, newRecord });
			m_routes.emplace_back(std::move(newRecord));
		}
		catch (std::exception &)
		{
			undoEvents(eventLog);

			std::throw_with_nested(std::runtime_error("Failed during batch insertion of routes"));
		}
	}
}

void RouteManager::addRoute(const Route &route)
{
	LockType lock(m_routesLock);

	std::optional<RouteRecord> deletedRecord;

	auto existing = findRoute(route);

	if (existing != m_routes.end())
	{
		try
		{
			deleteFromRoutingTable(existing->registeredRoute);
		}
		catch (std::exception &)
		{
			std::throw_with_nested(std::runtime_error("Failed to evict old route when adding new route"));
		}

		deletedRecord = *existing;
		m_routes.erase(existing);
	}

	try
	{
		m_routes.emplace_back
		(
			RouteRecord{ route, addIntoRoutingTable(route) }
		);
	}
	catch (std::exception &)
	{
		//
		// Restore deleted record.
		//

		if (deletedRecord.has_value())
		{
			auto &r = deletedRecord.value();

			try
			{
				restoreIntoRoutingTable(r.registeredRoute);
				m_routes.emplace_back(r);
			}
			catch (std::exception &ex)
			{
				const auto err = std::string("Failed to restore evicted route during rollback: ").append(ex.what());
				m_logSink->error(err.c_str());
			}
		}

		//
		// Just rethrow because the error is from addIntoRoutingTable().
		//

		throw;
	}
}

void RouteManager::deleteRoutes(const std::vector<Route> &routes)
{
	LockType lock(m_routesLock);

	std::vector<EventEntry> eventLog;

	for (const auto &route : routes)
	{
		try
		{
			auto officialRecord = findRoute(route);

			if (m_routes.end() == officialRecord)
			{
				const auto err = std::wstring(L"Request to delete previously unregistered route: ")
					.append(FormatNetwork(route.network()));

				m_logSink->warning(common::string::ToAnsi(err).c_str());

				continue;
			}

			deleteFromRoutingTable(officialRecord->registeredRoute);
			eventLog.emplace_back(EventEntry{ EventType::DELETE_ROUTE, *officialRecord });
			m_routes.erase(officialRecord);
		}
		catch (std::exception &)
		{
			undoEvents(eventLog);

			std::throw_with_nested(std::runtime_error("Failed during batch removal of routes"));
		}
	}
}

void RouteManager::deleteRoute(const Route &route)
{
	LockType lock(m_routesLock);

	auto officialRecord = findRoute(route);

	if (m_routes.end() == officialRecord)
	{
		const auto err = std::wstring(L"Request to delete previously unregistered route: ")
			.append(FormatNetwork(route.network()));

		m_logSink->warning(common::string::ToAnsi(err).c_str());

		return;
	}

	deleteFromRoutingTable(officialRecord->registeredRoute);
	m_routes.erase(officialRecord);
}

std::list<RouteManager::RouteRecord>::iterator RouteManager::findRoute(const Route &route)
{
	return std::find_if(m_routes.begin(), m_routes.end(), [&route](const auto &candidate)
	{
		return EqualAddress(route.network(), candidate.route.network());
	});
}

//std::list<RouteManager::RouteRecord>::iterator RouteManager::findRoute(const Network &network)
//{
//	return std::find_if(m_routes.begin(), m_routes.end(), [&network](const auto &candidate)
//	{
//		return EqualAddress(network, candidate.route.network());
//	});
//}

RouteManager::RegisteredRoute RouteManager::addIntoRoutingTable(const Route &route)
{
	const auto node = ResolveNode(route.network().Prefix.si_family, route.node());

	MIB_IPFORWARD_ROW2 spec;

	InitializeIpForwardEntry(&spec);

	spec.InterfaceLuid = node.iface;
	spec.DestinationPrefix = route.network();
	spec.NextHop = node.gateway;
	spec.Metric = 0;
	spec.Protocol = MIB_IPPROTO_NETMGMT;
	spec.Origin = NlroManual;

	//
	// Do not treat ERROR_OBJECT_ALREADY_EXISTS as being successful.
	// Because it may not take route metric into consideration.
	//

	THROW_UNLESS(NO_ERROR, CreateIpForwardEntry2(&spec), "Register route in routing table");

	return RegisteredRoute { route.network(), node.iface, node.gateway };
}

void RouteManager::restoreIntoRoutingTable(const RegisteredRoute &route)
{
	MIB_IPFORWARD_ROW2 spec;

	InitializeIpForwardEntry(&spec);

	spec.InterfaceLuid = route.luid;
	spec.DestinationPrefix = route.network;
	spec.NextHop = route.nextHop;
	spec.Metric = 0;
	spec.Protocol = MIB_IPPROTO_NETMGMT;
	spec.Origin = NlroManual;

	THROW_UNLESS(NO_ERROR, CreateIpForwardEntry2(&spec), "Register route in routing table");
}

void RouteManager::deleteFromRoutingTable(const RegisteredRoute &route)
{
	MIB_IPFORWARD_ROW2 r = { 0};

	r.InterfaceLuid = route.luid;
	r.DestinationPrefix = route.network;
	r.NextHop = route.nextHop;

	auto status = DeleteIpForwardEntry2(&r);

	if (ERROR_NOT_FOUND == status)
	{
		status = NO_ERROR;

		const auto err = std::wstring(L"Attempting to delete route which was not present in routing table, " \
			"ignoring and proceeding. Route: ").append(FormatRegisteredRoute(route));

		m_logSink->warning(common::string::ToAnsi(err).c_str());
	}

	THROW_UNLESS(NO_ERROR, status, "Delete route in routing table");
}

void RouteManager::undoEvents(const std::vector<EventEntry> &eventLog)
{
	//
	// Rewind state by processing events in the reverse order.
	//

	for (auto it = eventLog.rbegin(); it != eventLog.rend(); ++it)
	{
		try
		{
			switch (it->type)
			{
				case EventType::ADD_ROUTE:
				{
					auto officialRecord = findRoute(it->record.route);

					if (m_routes.end() == officialRecord)
					{
						throw std::runtime_error("Internal state inconsistency in route manager");
					}

					deleteFromRoutingTable(it->record.registeredRoute);
					m_routes.erase(officialRecord);

					break;
				}
				case EventType::DELETE_ROUTE:
				{
					restoreIntoRoutingTable(it->record.registeredRoute);
					m_routes.emplace_back(it->record);

					break;
				}
				default:
				{
					throw std::logic_error("Missing case handler in switch clause");
				}
			}

		}
		catch (std::exception &ex)
		{
			const auto err = std::string("Attempting to rollback state: ").append(ex.what());
			m_logSink->error(err.c_str());
		}
	}
}

//static
void NETIOAPI_API_
RouteManager::RouteChangeCallback(void *context, MIB_IPFORWARD_ROW2 *row, MIB_NOTIFICATION_TYPE notificationType)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(row);
	UNREFERENCED_PARAMETER(notificationType);

	// own route is deleted - add back
	// own route is updated - remove and add back
	// default route is added - ?
	// default route is updated - ?
	//
	// recall that we see the route as it existed before the most recent change




	//auto owner = reinterpret_cast<RouteManager *>(context);

	//LockType lock(owner->m_routesLock);

	//row->DestinationPrefix.
}

// static
std::wstring RouteManager::FormatRegisteredRoute(const RegisteredRoute &route)
{
	std::wstringstream ss;

	if (AF_INET == route.network.Prefix.si_family)
	{
		std::wstring gateway(L"\"On-link\"");

		if (0 != route.nextHop.Ipv4.sin_addr.s_addr)
		{
			gateway = common::string::FormatIpv4(route.nextHop.Ipv4.sin_addr.s_addr);
		}

		ss << common::string::FormatIpv4(route.network.Prefix.Ipv4.sin_addr.s_addr, route.network.PrefixLength)
			<< L" with gateway " << gateway
			<< L" on interface with LUID 0x" << std::hex << route.luid.Value;
	}
	else if (AF_INET6 == route.network.Prefix.si_family)
	{
		std::wstring gateway(L"\"On-link\"");

		const uint8_t *begin = &route.nextHop.Ipv6.sin6_addr.u.Byte[0];
		const uint8_t *end = begin + 16;

		if (0 != std::accumulate(begin, end, 0))
		{
			gateway = common::string::FormatIpv6(route.nextHop.Ipv6.sin6_addr.u.Byte);
		}

		ss << common::string::FormatIpv6(route.network.Prefix.Ipv6.sin6_addr.u.Byte, route.network.PrefixLength)
			<< L" with gateway " << gateway
			<< L" on interface with LUID 0x" << std::hex << route.luid.Value;
	}
	else
	{
		ss << L"Failed to format route details";
	}

	return ss.str();
}

}
