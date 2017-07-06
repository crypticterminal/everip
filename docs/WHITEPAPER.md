# Whitepaper: The EVER/IP Networking Suite

EVER/IP is a new way to think about building the Internet by redefining how packets are created and routed and also redefining who *owns* the Internet, by making IP addresses backed by public/private cryptographic key pairs.

This whitepaper aims to describe and outline the EVER/IP Networking Suite.

*Work in Progress*

## Table of Contents

0. [Introduction](#introduction)
0. [History and Background](#history-and-background)
0. [IP Address as a Public Commodity](#ip-address-as-a-public-commodity)
0. [ICO and Distribution](#ico-and-distribution)
0. [Implications](#economic-implications)
0. [Design Goals](#design-goals)
0. [Protocol: Related Work](#protocol-related-work)
0. [Feature Set](#feature-set)
0. [Routing Engine](#routing-engine)
0. [Encryption Engine](#encryption-engine)
0. [Conclusion](#conclusion)

## Introduction

The Internet may be the most important discovery and invention of mankind. Its explosive growth has fuelled countless industries and its significance is perhaps only second to the discovery of the personal computer.

In the 1980s when the Internet was first developed, computers were of limited computational resource. Therefore it was decided that in order to effectively route millions of packets per second, trade-offs had to be made and thus the Internet was split into two "levels":

1. A memory-bound lower level to be concerned with transporting data packets between neighbouring network nodes (called IMPs, known today as routers)
2. A higher level to be concerned with various end-to-end aspects of the data transmission (known today as TCP/IP).

The immediate lack of computational power has forced the implementation of the Internet to become memory-bound and thus its core infrastructure requires tremendous dedication, resource and power. The complexity in managing this core infrastructure has become a major industry, keeping the cost of communication relatively high and core growth relatively low.

In this paper, we introduce a solution for a better Internet with the Elastic Versatile Encrypted Relay for IP (EVER/IP) Networking Suite. EVER/IP is routing software that does not incorporate expensive memory routing tables and instead uses the CPU to calculate forwarding direction based entirely on local information.

This is finally possible due greatly in part to the iPhone® and other smartphones of its generation that have pushed for smaller, more efficient, more powerful processors and the FABs such as TSMC in Taiwan who have raced to scale production. EVER/IP aims to unleash this power, bringing-down the cost of communications worldwide and beyond.

## History and Background

The Japanese government (and perhaps other localities) have very strict laws on Internet security, but many realise that the Internet itself is insecure by its very nature. EVER (the Elastic Versatile Encrypted Relay) as a protocol was first developed in 2011 by Kristopher Tate in Kyoto, Japan and was started after receiving a very rare "Administrative Guidance" or Gyosei-Shido from the government of Japan regarding Internet security.

The first release was on the 12th of December, 2012 [1]

Today, EVER/IP is part of a working group inside of the Japanese Ministry of Economy, Trade and Industry (METI) to bring down the cost of communications by autonomizing network discovery and reach.

## IP Address as a Public Commodity

> The Internet must always remain open, yet commercially viable.
>
> The humble IP Address should become a tradable commodity.
> - kristopher tate

Net neutrality is a very specific, yet important topic. The problem is strictly tied to Internet service providers and governments regulating the Internet. We at connectFree believe that this is possible entirely because the addresses or "digital land" on the Internet is owned entirely by commercial entities.

While we as well are a commercial entity, our goals are much more inline with computer makers and digital artisans -- we want to enable users to own their devices and property and we strongly believe that an IP address should be your property.

To reiterate, today's networks are not independent and whole blocks of network addresses can be owned by large companies.

For example, Apple Inc. owns all IP addresses that start with the number 17 [2]. Ford Motor Company owns all IP addresses that start with the number 19 [2]. Each company owns 16,581,375 addresses. There are only 4,294,967,296 ip addresses available on the Internet, which means that these companies own approximately 1/256th of the entire Internet.

In contrast, EVER/IP assigns one IP Address to one device, for the lifetime of the device. The IP Address cannot be revoked later and if the device is destroyed, the IP Address is lost with the device. EVER/IP supports up to 2<sup>120</sup> (1,329,227,995,784,915,872,903,807,060,280,344,576) IP Addresses. This is 309,485,009,821,345,068,724,781,056 times more IP Addresses than what the current Internet supports.

That is why we believe that it is important for IP Addresses to be a public commodity.

## ICO and Distribution

If we are to create a truly distributed, authenticated and secure Internet, it needs to be commercially viable. Today's Internet as infrastructure is commercially viable and so are the properties that run above it.

### ICO

Our answer to this problem is to "Tokenize" the IP Address and sell it to distributors and also via an ICO (Initial Coin Offering). This creates incentives for commercial entities to bundle this new connectivity software with their devices and to market the solution to their users.

### Distribution

There are two modes of distribution: via our Ethereum "IPToken" and also via a commercial distributor network.

We have made physical labels to identify and track IP Addresses and Ethereum IPTokens will be traceable for these physical labels and license files.

## Design Goals

0. Create an Internet that could work on multiple planets.
0. Create an Internet that can be owned by both things and people.
0. Create an Internet without dedicated core routing infrastructure.
0. Maintain backwards compatibility with existing IP products and solutions.
0. Provide a solution that is both secure and elastic, removing the need for network administrators.

## Economic Implications

The implications of our work is that if we succeed, the cost for communication will greatly drop. We see this as a boon for the global economy and perhaps the start of a multi-planetary economy. The current Internet is too centralised for its own good and it requires the help of large corporations to mediate.

Let it be known that we are not against telecommunication corporations. Instead, we see this software as becoming a great help to their core mission. Telecommunication corporations may become more lean and thus profit margins will increase.

Our work focuses on the Internet of Things and building a network of things, instead of simply placing Things on the Internet. Many corporations (especially in Japan) who produce social infrastructure technologies and solutions cannot pay for monthly Internet access per device. Their business models require that any service or part must be incorporated into its Bill of Materials (BOM). We see a huge gap in this market that EVER/IP is poised to take part in. It is our great hope that EVER/IP helps to create a new connected economy, both on Earth and beyond.


## Protocol: Related Work

In the wireless connectivity field, self-configuring protocols such as BATMAN [1], HSLS [2] and OLSR [3] are well known and deployed. These protocols try to relieve the configuration burden at the edge, but only by centralising configuration and management. Cisco Meraki [4] is a commercial solution that aims to help network administrators by keeping configuration in the cloud, but these solutions simply mask the core problems with more configuration.

Experimental solutions such as VRR [5], CJDNS [6] and SAFE Network [7] use Distributed Hash Tables (DHTs) to improve the scalability of routing. However, such DHT-based solutions assume that the nodes exist in a Euclidean space and rely an XOR metric. On the contrary, it has been shown that Euclidean spaces are not well suited to represent Internet nodes [8] and in our implementation EVER/IP assumes nodes interact within an arbitrary connectivity graph.

## Feature Set

1. Each device is assigned a cryptographically signed and authenticated public and private key.
2. Said assigned public/private key is used to generate a cryptographic hash that will represent the node's IP address.
3. All communications are encrypted at OSI Layer-3, so there is no need to integrate TLS into the application. (TLS can still be used if required)
4. Packets are routed over any media, so long as another EVER/IP state machine is on the other side. We have implementations for Layer-2 (802.3 Ethernet/802.11 WiFi/Fibre) and UDP connectivity at Layer-3.
5. Existing applications just work: EVER/IP reports itself to the Operating System as a VPN.
6. No need for network administrators: network configuration is instant and autonomous.

## Routing Engine

### Traditional Routing

Traditional Routing requires not only devices with addresses, but also routers that forward packets closer to their destination. The routing functionality is provided by special equipment called a router.

Routers are administrated by individuals and organisations who configure forwarding tables that determine the next hop for the packet to reach its destination. At each hop, the next router then repeats this process using its own configured forwarding tables, and so on until the packet reaches its destination.

An IP Address is sufficient enough to route a packet through the network, although this is only because most of the complexity is pushed to the routers and the configuration of said routers. If a table is misconfigured, network "Black Holes" may develop and can only be fixed manually by the aid of network engineers.


![Traditional Routing](/docs/traditional-routing.png)


### Label Switching / CJDNS Routing

In a label-switched environment, forwarding decisions are not made via an address, but instead using a set of conditions provided by stack of instructions called "labels". Labels are fast and useful, but without information on which label goes to which address, the labels are useless. In a traditional Multiprotocol Label Switching (MPLS) environment, labels are configured much like routing tables. In experimental technologies such as CJDNS, DHTs are used to share routes amongst other peers. The down-side to this technique is two-fold: 1) lots of traffic must be dedicated to sharing these labels 2) there is no guarantee that any labels could be found.

Incidentally, the developers behind CJDNS have as of the writing of this paper have abandoned peer-based sharing in support of a supernode/subnode-based design. This means that without core infrastructure, nodes have limited ability to discover routes to each other and places burden on supernodes to sustain uptime.


![MPLS/CJDNS Routing](/docs/label-based-routing.png)


### EVER/IP Routing

EVER/IP Routing is different from both Traditional Routing and Label Switching / CJDNS Routing for the following reasons:

1. A node's graph ID encodes its location inside of an arbitrary connectivity graph.
1. Based on this encoded graph ID, local information is used to forward packets.
2. No routing or lookup tables must be configured to instigate routing.

Source: https://github.com/connectFree/everip/blob/master/src/treeoflife/treeoflife.c

![EVER/IP Routing](/docs/everip-based-routing.png)

## Encryption Engine

Source: https://github.com/connectFree/everip/blob/master/src/centraldogma/crypto.c

The Encryption Engine engine is based on the routines provided in the libsodium library and utilises the XSalsa20 stream cipher with Poly1305 authentication. XSalsa20 is a stream cipher based upon Salsa20 but with a much longer nonce: 192 bits instead of 64 bits. Like Salsa20, XSalsa20 is immune to timing attacks and provides its own 64-bit block counter to avoid incrementing the nonce after each block.

There is one stage dedicated to bootstrapping nodes; two stages required before two-way authenticated crypto-communication can commence; and the last stage (4) that signifies establishment. 

1. Bootstrap - sent when the other party's key is not yet known
2. Attention
3. Key Exchange
4. Established - packets are Poly1305 authenticated.

## Conclusion

The cost of secure communications is still too high for appliance and social infrastructure manufacturers to harness. End-users still are afraid of networking and at many institutions, users are forbidden from accessing the network on their terms.

The godfathers of the Internet believed in the concept of end-to-end connectivity [9] and because of the exhaustion of the IP Address space, it is harder than ever to directly connect nodes together.

EVER/IP provides a clean slate and new thinking to a much required field of significant importance and we aim to make it the next standard of the Internet through transparency and dedication to our trade.

[1]: http://www.itmedia.co.jp/news/articles/1212/12/news042.html
[2]: https://en.wikipedia.org/wiki/List_of_assigned_/8_IPv4_address_blocks#List_of_assigned_.2F8_blocks
[1]: https://en.wikipedia.org/wiki/B.A.T.M.A.N.
[2]: https://en.wikipedia.org/wiki/Hazy_Sighted_Link_State_Routing_Protocol
[3]: https://en.wikipedia.org/wiki/Optimized_Link_State_Routing_Protocol
[4]: https://meraki.cisco.com/
[5]: https://www.microsoft.com/en-us/research/publication/virtual-ring-routing-network-routing-inspired-dhts/
[6]: https://github.com/cjdelisle/cjdns
[7]: https://github.com/maidsafe
[8]: http://domino.research.ibm.com/library/cyberdig.nsf/papers/492D147FCCEA752C8525768F00535D8A
[9]: https://en.wikipedia.org/wiki/End-to-end_principle

