#pragma once

#include <string>
#include <memory>
#include <vector>
#include <list>
#include <stdexcept>
#include <optional>
#include <mutex>
#include <winsock2.h>
#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

namespace routemanager {

using Network = IP_ADDRESS_PREFIX;
using NodeAddress = SOCKADDR_INET;

bool EqualAddress(const Network &lhs, const Network &rhs);
bool EqualAddress(const NodeAddress &lhs, const NodeAddress &rhs);

class Node
{
public:

	Node(const std::wstring &deviceName)
		: m_deviceName(deviceName)
	{
	}

	Node(const NodeAddress &gateway)
		: m_gateway(gateway)
	{
	}

	const std::optional<std::wstring> &deviceName() const
	{
		return m_deviceName;
	}

	const std::optional<NodeAddress> &gateway() const
	{
		return m_gateway;
	}

	bool operator==(const Node &rhs) const
	{
		if (m_deviceName.has_value())
		{
			return rhs.deviceName().has_value()
				&& 0 == _wcsicmp(m_deviceName.value().c_str(), rhs.deviceName().value().c_str());
		}

		return rhs.gateway().has_value()
			&& EqualAddress(m_gateway.value(), rhs.gateway().value());
	}

private:

	std::optional<std::wstring> m_deviceName;
	std::optional<NodeAddress> m_gateway;
};

class Route
{
public:

	Route(const Network &network, const std::optional<Node> &node)
		: m_network(network)
		, m_node(node)
	{
	}

	const Network &network() const
	{
		return m_network;
	}

	const std::optional<Node> &node() const
	{
		return m_node;
	}

	bool operator==(const Route &rhs) const
	{
		if (m_node.has_value())
		{
			return rhs.node().has_value()
				&& EqualAddress(m_network, rhs.network())
				&& m_node.value() == rhs.node().value();
		}

		return false == rhs.node().has_value()
			&& EqualAddress(m_network, rhs.network());
	}

private:

	Network m_network;
	std::optional<Node> m_node;
};

class RouteManager
{
public:

	RouteManager() = default;
	~RouteManager();

	RouteManager(const RouteManager &) = delete;
	RouteManager &operator=(const RouteManager &) = delete;
	RouteManager(RouteManager &&) = default;

	void addRoutes(const std::vector<Route> &routes);
	void addRoute(const Route &route);

	void deleteRoutes(const std::vector<Route> &routes);
	void deleteRoute(const Route &route);

private:

	std::list<Route> m_routes;

	std::recursive_mutex m_routesLock;

	// Find a route based on network and mask.
	std::list<Route>::iterator findRoute(const Route &route);

	// thread handle
};

}
