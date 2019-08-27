#include "stdafx.h"
#include "../../winnet/winnet.h"
#include "../../winnet/routemanager.h"
#include <iostream>

void __stdcall ConnectivityChanged(bool connected, void *)
{
	std::wcout << (0 != connected? L"Connected" : L"NOT connected") << std::endl;
}

int main()
{
	//wchar_t *alias = nullptr;

	//const auto status = WinNet_GetTapInterfaceAlias(&alias, nullptr, nullptr);

	//switch (status)
	//{
	//	case WINNET_GTIA_STATUS::FAILURE:
	//	{
	//		std::wcout << L"Could not determine alias" << std::endl;
	//		break;
	//	}
	//	case WINNET_GTIA_STATUS::SUCCESS:
	//	{
	//		std::wcout << L"Interface alias: " << alias << std::endl;
	//		WinNet_ReleaseString(alias);
	//	}
	//};



	//uint8_t currentConnectivity = 0;

	//const auto status = WinNet_ActivateConnectivityMonitor(ConnectivityChanged, &currentConnectivity, nullptr, nullptr);

	//std::wcout << L"Current connectivity: "
	//	<< (0 != currentConnectivity ? L"Connected" : L"NOT connected") << std::endl;



	routemanager::Network network{ 0 };

	//network.PrefixLength = 1;
	//network.Prefix.si_family = AF_INET;
	//network.Prefix.Ipv4.sin_family = AF_INET;
	//network.Prefix.Ipv4.sin_addr.s_net = 0x80;

	//network.PrefixLength = 1;
	//network.Prefix.si_family = AF_INET;
	//network.Prefix.Ipv4.sin_family = AF_INET;
	//network.Prefix.Ipv4.sin_addr.s_net = 0;

//	auto node = routemanager::Node(L"Mullvad");
//	auto node = routemanager::Node(L"VirtualBox Host-Only Network #2");




	network.PrefixLength = 32;
	network.Prefix.si_family = AF_INET;
	network.Prefix.Ipv4.sin_family = AF_INET;
	network.Prefix.Ipv4.sin_addr.s_addr = 0x439ad5b9;







	std::vector<routemanager::Route> routes;

//	routes.emplace_back(routemanager::Route(network, std::make_optional<>(node)));
	routes.emplace_back(routemanager::Route(network, std::nullopt));

	auto rm = routemanager::RouteManager(routes);

	std::wcout << L"Paused" << std::endl;
	_getwch();

    return 0;
}

