# blackhat23-melsoft
Tools to dissect the Mitsubishi Electric MELSOFT protocol when used to communicate with Safety PLCs, specifically designed to help security teams to investigate network streams independently; multiple PCAPs are also distributed as example to boost the initial learning phase. 

The dissector has also a fully working expert section warning on potential attacks related with the authentication and authorization stages, specifically **CVE-2021-20594**, **CVE-2021-20597**, **CVE-2021-20598**, **CVE-2021-20599**, **NN-2021-0019**.

This material is released in conjunction with our presentation at Black Hat MEA 23 ["Safety is not Security: Exploring Authentication and Authorization in Mitsubishi Electric iQ-R Safety PLCs"](https://blackhatmea.com/session/safety-not-security-exploring-authentication-and-authorization-mitsubishi-electric-iq-r).

## Installation
The Lua script is natively supported by Wireshark and there are no required dependencies for using it. The script needs to be placed in the right directory depending on the operating system used. Below are the reported working paths used during development:

* Linux / MacOS: ```~/.config/wireshark/plugins```
* Windows: ```%appdata%\Wireshark\plugins```

Note that in some systems the plug-in folder could be missing. To fix this issue, just create it manually and place the Lua script in it.

More detailed information about plug-in installation can be found at the official web page:
[https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)

## Features

<img width="1607" alt="1" src="https://github.com/NozomiNetworks/blackhat23-melsoft/assets/79845366/33031748-da93-4d4b-9938-e6ed4a72f12c">

The dissector is able to parse network packets having magic bytes `0x5701` (for requests) and `0xd700` (for responses), which are the main ones sent by the engineering workstation software (e.g., GX Works3) to the PLC, and to split them into the four sections: Ethernet Header, Command Header, Command Data, and Ethernet Footer.

Notably, it is also able to in-depth dissect the payload of the following commands, which are the ones involved during the exploitation of CVE-2021-20594, CVE-2021-20597, CVE-2021-20598, CVE-2021-20599, and NN-2021-0019:
* `0x0131` "Username Login", transmitted by the engineering workstation software to the PLC during the authentication phase (step 1/2);
* `0x0132` "Password Login", transmitted by the engineering workstation software to the PLC during the authentication phase (step 2/2;
* `0x0134` "Read User Information from PLC B", transmitted by the engineering workstation software to the PLC while accessing the "Read user information from PLC" functionality;
* `0x1133` "User Information Registration", transmitted by the engineering workstation software to the PLC while registering a new user or updating their password.

The dissector is designed to be completely modular, and can be expanded at will with support for other payloads. Some other command codes discovered during our analysis are included (although dissection of these payloads is not provided).

Besides dissecting the packet content, the dissector has a fully working Expert section that warns of every potential attack concerning the authentication and authorization phases. For instance, here is the Expert window of a PCAP while attempting to exploit CVE-2021-20594.

<img width="1301" alt="2" src="https://github.com/NozomiNetworks/blackhat23-melsoft/assets/79845366/e68d476c-d9a1-49a9-8bf8-ddb40fda2756">

You may test the dissector with the following provided PCAP files:
* `legitimate_user_addition_plc_stop_test.pcapng`, a PCAP recorded while doing the following legitimate actions: user registration, remote control stop, and safety run mode change to test mode. Samples of `0x1133` "User Information Registration" packets are included, which are the ones that may be abused in the exploitation of CVE-2021-20597;
* `cve_2021_20594_username_bruteforce.pcapng`, a PCAP recorded while doing a username brute-force attack to exploit CVE-2021-20594;
* `cve_2021_20598_20599_nn_2021_0019_attack_demo_1.pcapng`, a PCAP recorded while performing the Attack Demo #1 explained in our talk (pass-the-token attack, disabling of the safety routines, and remote lock of the PLC by an unauthenticated attacker capable of sniffing network packets between the engineering workstation software and the PLC). It includes the exploit packets of CVE-2021-20598, CVE-2021-20599, and NN-2021-0019.

We would like to emphasize that the functionality of the dissector is the result of our analysis and reflects an attacker’s reverse engineering of the Mitsubishi Electric MELSOFT protocol.
