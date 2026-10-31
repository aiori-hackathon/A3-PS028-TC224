# Happy Eyeballs Webtester

This is the source code for the online Happy Eyeballs webtester: [www.happy-eyeballs.net](https://www.happy-eyeballs.net).
It was initially developed as part of the paper "Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations" by Patrick Sattler.
Please use [the provided citation](#citation)

The current development team is:
- [Patrick Sattler](https://www.patricksattler.eu)
- [Johannes Zirngibl](https://zirngibl.github.io)
- Matthias Kirstein
- Tim Betzer



## Install

We use [Ansible](https://docs.ansible.com/ansible/latest/index.html) to automatically set up and deploy this tool to hosts.

### Prerequisites

- [Ansible](https://docs.ansible.com/ansible/latest/index.html) on the local machine
- An interface where [tc netem](https://www.man7.org/linux/man-pages/man8/tc-netem.8.html) delay is working (usually needs to be non-virtual)
- 2 IPv4 and 2 IPv6 addresses for the nameserver
- One IPv4 and IPv6 address for the webtester frontend
- One IPv4 and IPv6 address to check if the client actually supports both IP versions and for tests without netem delays
- As many IPv4 and IPv6 addresses as delays should be tested (our default configuration uses 21 delays)
- One IPv4 and IPv6 address for HTTP/3 tests
- One IPv4 and IPv6 address for Happy Eyeballs version 3 related tests

### Configuration

Check the [example configuration file](./setup/hosts.yml) for a complete example setup.
The main points to update are the host that the webtester should be deployed to, the domains, network interfaces, IP addresses, and delays.
For detailed explanations of each configuration option, refer to the inline comments within the example config.

### Ansible

After configuring the host in `setup/hosts.yml`, the setup playbook can be run using `ansible-playbook setup/setup.yml -i setup/hosts.yml`.

We added several tags to control the setup process:
- `system`: installs required packages (such as Docker) and creates the user
- `interface`: assigns the configured addresses to the interfaces and configures the tc delays
  - `interface-ip-delete`: include this tag specifically if you want to delete the configured addresses from the interface
- `dns`: sets up the nameserver
- `caddy`: sets up caddy
- `webtester`: sets up the webtester (frontend)
- `resultupload`: sets up the result upload server
- `packetcapture`: sets up the packet capture service and tshark service

Note: all tags have their own "subtags" (such as `system-podman`) for only executing specific subtasks.
Those can be found in the `tasks/main.yml` inside the individual ansible roles.


## Helpful setup and debug commands

### Drop tc config

`tc qdisc del dev ${interface} root`

## Citation

Citation to use when referring to this project:

```
@inproceedings{sattler2025happyeyeballs,
    title = {{Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations}},
    author = {Sattler, Patrick and Kirstein, Matthias and Wüstrich, Lars and Zirngibl, Johannes and Carle, Georg},
    booktitle = {Proceedings of the 2025 Internet Measurement Conference},
    year = {2025},
    location = {Madison, WI, USA},
    abbreviation = {IMC'25},
    publisher = {ACM},
    month = oct,
    homepage = {https://www.happy-eyeballs.net/},
    month_numeric = {10}
}
```

## License

This project is licensed under the Mozilla Public License Version 2.0 ([see LICENSE](LICENSE)).

UI elements in `setup/webtester/src/components/ui` are from shadcn and licensed with [MIT](LICENSES/MIT.txt)
