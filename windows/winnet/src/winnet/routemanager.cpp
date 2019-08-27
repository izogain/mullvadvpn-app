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

NET_LUID InterfaceLuidFromDefaultRoute(ADDRESS_FAMILY family)
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

	return annotated[0].route->InterfaceLuid;
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

NET_LUID InterfaceLuidFromNode(ADDRESS_FAMILY family, const std::optional<routemanager::Node> &optionalNode)
{
	if (false == optionalNode.has_value())
	{
		return InterfaceLuidFromDefaultRoute(family);
	}

	const auto &node = optionalNode.value();

	if (node.deviceName().has_value())
	{
		NET_LUID luid;

		if (0 != ConvertInterfaceAliasToLuid(node.deviceName().value().c_str(), &luid))
		{
			const auto ansiName = common::string::ToAnsi(node.deviceName().value());
			const auto err = std::string("Unable to derive interface LUID from interface alias: ").append(ansiName);

			throw std::runtime_error(err);
		}

		return luid;
	}
	else
	{
		return InterfaceLuidFromGateway(node.gateway().value());
	}
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

routemanager::NodeAddress InterfacePrimaryGateway(NET_LUID iface, ADDRESS_FAMILY family)
{
	const DWORD adapterFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
		| GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_INCLUDE_GATEWAYS;

	Adapters adapters(family, adapterFlags);

	for (auto adapter = adapters.next(); nullptr != adapter; adapter = adapters.next())
	{
		if (adapter->Luid.Value != iface.Value)
		{
			continue;
		}

		auto gateways = IsolateGatewayAddresses(adapter->FirstGatewayAddress, family);

		if (gateways.empty())
		{
			std::stringstream ss;

			ss << "Adapter with LUID 0x" << std::hex << iface.Value << " does not appear to have any "
				<< "gateways configured for " << (AF_INET == family ? "IPv4" : "IPv6");

			throw std::runtime_error(ss.str());
		}

		return ConvertSocketAddress(gateways[0]);
	}

	throw std::runtime_error("Could not find interface with matching LUID");
}

routemanager::NodeAddress SelectRouteGateway(const routemanager::Route &route, NET_LUID iface)
{
	//
	// We've already selected the interface to use.
	// If it was selected based on a gateway in the route spec, we return that gateway.
	//

	if (route.node().has_value()
		&& route.node().value().gateway().has_value())
	{
		return route.node().value().gateway().value();
	}

	return InterfacePrimaryGateway(iface, route.network().Prefix.si_family);
}

void AddRoute(const routemanager::Route &route)
{
	const auto iface = InterfaceLuidFromNode(route.network().Prefix.si_family, route.node());
	const auto nextHop = SelectRouteGateway(route, iface);

	MIB_IPFORWARD_ROW2 spec;

	InitializeIpForwardEntry(&spec);

	spec.InterfaceLuid = iface;
	spec.DestinationPrefix = route.network();
	spec.NextHop = nextHop;
	spec.Metric = 0;
	spec.Protocol = MIB_IPPROTO_NETMGMT;
	spec.Origin = NlroManual;

	//
	// Do not treat ERROR_OBJECT_ALREADY_EXISTS as being successful.
	// Because it may not take route metric into consideration.
	//

	THROW_UNLESS(NO_ERROR, CreateIpForwardEntry2(&spec), "Add route entry");
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
			throw std::runtime_error("Invalid network address");
		}
	}
}

RouteManager::~RouteManager()
{
	// TODO: signal monitoring thread to shut down

	std::vector<Route> routes;

	std::copy(m_routes.begin(), m_routes.end(), std::back_inserter(routes));

	try
	{
		deleteRoutes(routes);
	}
	catch (std::exception &ex)
	{
		// TODO: log
	}
}

void RouteManager::addRoutes(const std::vector<Route> &routes)
{
	// Taking the lock is not strictly necessary but makes this method atomic.
	LockType lock(m_routesLock);

	std::vector<Route> added;
	added.reserve(routes.size());

	for (const auto &route : routes)
	{
		try
		{
			addRoute(route);
			added.emplace_back(route);
		}
		catch (std::exception &ex)
		{
			try
			{
				deleteRoutes(added);
			}
			catch (std::exception &ex)
			{
				// TODO: log
			}

			throw;
		}
	}
}

void RouteManager::addRoute(const Route &route)
{
	LockType lock(m_routesLock);

	auto existing = findRoute(route);

	if (existing != m_routes.end())
	{
		deleteRoute(*existing);
		m_routes.erase(existing);
	}

	AddRoute(route);
	m_routes.emplace_back(route);
}

void RouteManager::deleteRoutes(const std::vector<Route> &routes)
{
	// TODO: do we need locking?
	LockType lock(m_routesLock);
}

void RouteManager::deleteRoute(const Route &route)
{
	LockType lock(m_routesLock);

	DeleteIpForwardEntry2()

}

std::list<Route>::iterator RouteManager::findRoute(const Route &route)
{
	return std::find_if(m_routes.begin(), m_routes.end(), [&route](const auto &candidate)
	{
		return EqualAddress(route.network(), candidate.network());
	});
}

}
