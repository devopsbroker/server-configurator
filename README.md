# DevOpsBroker
DevOpsBroker delivers enterprise-level software tools to maximize individual and organizational ability to deliver applications and services at high velocity

## Ubuntu 18.04 Server Configurator ![New Release](images/new-icon.png)

The DevOpsBroker Ubuntu 18.04 Server Configurator is a complete turn-key solution for configuring a fresh installation of Ubuntu 18.04 Server.

### Current Release
**July 10th, 2019:** server-configurator 1.0.0 was released

### Installation Overview
1. Download the latest Ubuntu 18.04 Server ISO from [Ubuntu 18.04 Releases](http://releases.ubuntu.com/18.04/)

2. Install Ubuntu 18.04 Server

3. Download the latest release of [server-configurator](https://github.com/devopsbroker/server-configurator/releases/download/1.0.0/server-configurator_1.0.0_amd64.deb) and its [SHA256 Checksum](https://github.com/devopsbroker/server-configurator/releases/download/1.0.0/SHA256SUM)

4. Verify the **server-configurator** package against its SHA256 checksum

   * `sha256sum --check ./SHA256SUM`

5. Make sure the Ubuntu **universe** repository is configured properly

   * `sudo add-apt-repository universe`


6. Install the **server-configurator** package

   * `sudo apt install ./server-configurator_1.0.0_amd64.deb`


7. Configure your server

   * `sudo configure-server`


### Bugs / Feature Requests

Please submit any bugs or feature requests to GitHub by creating a [New issue](https://github.com/devopsbroker/server-configurator/issues)
