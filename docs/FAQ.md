# EVER/IP(r) Frequently Asked Questions

EVER/IP is a relatively new technology and you might have some questions about it.
Here we aim to provide you with some answers to your questions.

- [GENERAL](#general)
  * [What is EVER/IP?](#what-is-everip)
  * [Why Now? Why was EVER/IP not developed sooner?](#why-now-why-was-everip-not-developed-sooner)
  * [What makes EVER/IP a unique solution?](#what-makes-everip-a-unique-solution)
  * [What is the problem EVER/IP is solving?](#what-is-the-problem-everip-is-solving)
  * [What are some of the best use cases for EVER/IP?](#what-are-some-of-the-best-use-cases-for-everip)
  * [What platforms does EVER/IP run on?](#what-platforms-does-everip-run-on)
- [POLICY](#policy)
  * [Does EVER/IP solve Net Neutrality?](#does-everip-solve-net-neutrality)
- [TECHNICAL](#technical)
  * [Why use IPv6 an an API? Why not make your own API?](#why-use-ipv6-an-an-api-why-not-make-your-own-api)
  * [How is EVER/IP different from traditional Internet routing?](#how-is-everip-different-from-traditional-internet-routing)
  * [Is there a minimum number of devices that have to be online for EVER/IP to work?](#is-there-a-minimum-number-of-devices-that-have-to-be-online-for-everip-to-work)
  * [Is EVER/IP a Static or Global address?](#is-everip-a-static-or-global-address)
  * [What is the condition for connectivity?](#what-is-the-condition-for-connectivity)
- [DISTRIBUTION](#distribution)
  * [How does a device get assigned an EVER/IP address?](#how-does-a-device-get-assigned-an-everip-address)
  * [How can I obtain an EVER/IP Address?](#how-can-i-obtain-an-everip-address)
  * [Can EVER/IP be bought through cryptographic currencies?](#can-everip-be-bought-through-cryptographic-currencies)
- [LEGAL](#legal)
  * [Who develops and owns EVER/IP?](#who-develops-and-owns-everip)
  * [Can I use the EVER/IP trademark?](#can-i-use-the-everip-trademark)
 
# GENERAL

## What is EVER/IP?

EVER/IP is a new way to think about building the Internet by redefining who *owns* the Internet.  When the Internet was first developed in the 1980s, the Internet has lacked a truly distributed means of deciding who owns each IP address on the Internet. It instead relies on an archaic system of bureaucratic organizations known as the "Internet Assigned Numbers Authority" or IANA which has costly operations throughout the world. With EVER/IP, IP Addresses can be backed by public/private cryptographic key pairs and thus IP addresses may become established as property.

## Why Now? Why was EVER/IP not developed sooner?

The reason is hard rooted in the economics of scale.

In the 1980s when the Internet was first developed, computers were of limited computational resource. Therefore, it was decided that in order to effectively route millions of packets per second, trade-offs had to be made and the Internet became a system of pre calculated routes that had to be saved in very fast, very expensive memory.

This lack of computational power forced the implementation of the current Internet to become memory-bound and thus its core infrastructure requires tremendous dedication, resource and electricity. The complexity in managing this core infrastructure has become a major industry, keeping the cost of communication relatively high and core growth relatively low.

Fast-forward three decades, EVER/IP is the first kind of routing software that does not require memory expensive routing tables, but instead uses the CPU to calculate forwarding direction based entirely on local information.

Being entirely local information driven, there is no need for expensive ISPs and Providers, thus reducing the cost of communication for people and things alike.

Thanks in part to the iPhone(r)<sup>(1)</sup> and other smartphones of its generation, the computing power that we have in our pocket is incredible. EVER/IP aims to unleash this power, bringing-down the cost of communications worldwide and beyond. 

Companies like Microsoft helped take us from yesterday's mainframe into the Personal Computer era with "micro-software." We aim to take humanity from today's mainframe (cloud) into the Personal Communications era with Micro Internet eXchanges (MIXes).

<sup>(1)</sup> iPhone(R) is a trademark of Apple Inc., registered in the U.S. and other countries.

## What makes EVER/IP a unique solution?

* You own your own IP Address for*ever*. No monthly costs.
* Your IP Address is authenticated, so that no one can become you.
* All communications are encrypted, which is very important for banking and infrastructure.
* Works with existing network technologies (WiFi, Ethernet, Fibre, etc.) so that there is no cost to rebuild networks
* Existing applications just work: EVER/IP reports itself to the Operating System as a VPN.
* No need for network administrators: network configuration is instant and autonomous.

While there are other dynamic routing solutions and VPNs that interface with the IPv6 address space, EVER/IP is the only IPv6 solution that can calculate forwarding direction based entirely on local information. Other open-source projects such as CJDNS, SAFE Network and IPFS use forms of memory-backed routing tables or route labels to facilitate connectivity.

In contrast, EVER/IP makes routing decisions by calculating differences between connected coordinates in a larger network graph. EVER/IP's low memory footprint gives it the edge in any embedded project or application.

## What is the problem EVER/IP is solving?

EVER/IP allows you to own your IP Address outright and helps you manage it in a complete autonomous fashion.

## What are some of the best use cases for EVER/IP?

EVER/IP allows devices and users to directly connect to their favorite applications and content.

In an EVER/IP enabled world, there is no need to be on the same network as your printer or file sharing server.
The whole network is one shared, secure VPN for devices and content to communicate.

## What platforms does EVER/IP run on?

As of July 1st, 2017, EVER/IP has builds for Linux (ARM, x86, x64), Mac OS and Windows(R) operating systems.

iOS is currently under heavy development.

# POLICY

## Does EVER/IP solve Net Neutrality?

A network that is built on EVER/IP would provide neutral footing for all those who partake because it is built on algorithms and cryptography instead of a social bureaucratic model where variables in the system can be controlled to the benefit of a few.

# TECHNICAL

## Why use IPv6 an an API? Why not make your own API?

EVER/IP is not IPv6, but we use IPv6 as an API to connect existing applications (VoIP, Web, Browsers, Games, SAMBA/File Sharing) to the EVER/IP routing technology.

Even though we do have our own advanced API, it would require having application developers recompile their applications and it would require developers to engineer their own compatibility layer.

Piggybacking off of IPv6 is smart for the future of the Internet because it does not waste the time developed in porting applications to IPv6.

EVER/IP addresses are not routed on the normal internet and so if they do not have a public/private key backed EVER/IP address and EVER/IP software, they will not be able to connect.

## How is EVER/IP different from traditional Internet routing?

In a traditional networking environment, the address space and subsequently each device's address is divided into networks and subnetworks, involving the designation of network or routing prefixes. Networks are not independent and whole blocks of network addresses can be owned by large companies.

For example, Apple Inc. [owns all IP addresses that start with the number 17][1]. Ford Motor Company [owns all IP addresses that start with the number 19][1]. Each company owns 16,581,375 addresses. There are only 4,294,967,296 ip addresses available on the Internet, which means that these companies own approximately 1/256th of the entire Internet.

In contrast, EVER/IP assigns one IP Address to one device, for the lifetime of the device. The IP Address cannot be revoked later and if the device is destroyed, the IP Address is lost with the device. EVER/IP supports up to 2<sup>120</sup> (1,329,227,995,784,915,872,903,807,060,280,344,576) IP Addresses. This is 309,485,009,821,345,068,724,781,056 times more IP Addresses than what the current Internet supports.

Traditional networking also requires that there be a network integrator to see that all network routes on a network are valid. In contrast, EVER/IP is a completely autonomous system that automatically detects links and routes based on local information. This requires no network integrator to operate and is perfect for network cameras and other appliance devices.

[1]: https://en.wikipedia.org/wiki/List_of_assigned_/8_IPv4_address_blocks#List_of_assigned_.2F8_blocks

![EVER/IP ADDRESSES](/docs/everip_addresses.png)

## Is there a minimum number of devices that have to be online for EVER/IP to work?

The minimum number of devices that must be online for connection is two.

EVER/IP works by connecting with other EVER/IP enabled devices to form a homogeneous network.

## Is EVER/IP a Static or Global address?

All EVER/IPs are global by nature and static because each EVER/IP Address is determined by a public/private key pair.
In other words, there is no such thing as a dynamic EVER/IP Address or a local EVER/IP Address.

## What is the condition for connectivity?
Connectivity is possible if there is a valid path for data can take between devices.

An example route may be the following:
```
A <--[WIFI]--> B  <--[ETHERNET]--> C <--[FIBRE OPTIC]--> D  <--[ETHERNET]--> E <--[USB]--> F
```

# DISTRIBUTION
## How does a device get assigned an EVER/IP address?

EVER/IP Addresses are not assigned, but instead installed into devices.

Once the IP Address is installed into the device, it is the IP Address of the device until uninstalled or the device itself can no longer operate.

## How can I obtain an EVER/IP Address?

For Manufacturers: please contact our distributors for more information.

Individuals can purchase online or through our distributor network.

If you are not sure, please do not hesitate to contact licensing at this address: <licensing@connectfree.co.jp>.

## Can EVER/IP be bought through cryptographic currencies?

We are currently planning an ICO and will have more information soon.

# LEGAL
## Who develops and owns EVER/IP?

EVER/IP is developed and owned by connectFree Corporation of Kyoto, Japan.

Open Source contributors help us from time to time as outlined on our [CONTRIBUTING](/CONTRIBUTING.md) page.

## Can I use the EVER/IP trademark?

No, not without a license. connectFree, the connectFree logo, EVER and EVER/IP are registered trademarks of connectFree Corporation in Japan and other countries. connectFree trademarks and branding may not be used without the express written permission of connectFree.

## Didn't answer your question? Please contact us!
Please do not hesitate to contact us at <licensing@connectfree.co.jp>.


