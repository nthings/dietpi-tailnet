# DietPi Tailscale Setup with Exit Node

A comprehensive guide and automation script for setting up Tailscale on DietPi nodes with exit node routing capabilities.

## Overview

This repository provides tools and instructions to configure a DietPi device as a Tailscale client that routes traffic through an exit node. It includes:

- Automated setup script for NAT/Masquerade configuration
- IP forwarding enablement for subnet routing
- Exit node configuration with LAN access
- Static IP configuration utilities

## Prerequisites

Before setting up Tailscale on your DietPi node, ensure you have:

- A DietPi device (Raspberry Pi, x86, or other supported hardware)
- Root/sudo access to the device
- An active internet connection
- A Tailscale account (free at [tailscale.com](https://tailscale.com))
- An exit node already configured in your Tailnet (optional, if you want to route traffic through it)

## Installation

### Step 1: Install Tailscale on DietPi

1. **Connect to your DietPi device via SSH:**
   ```bash
   ssh root@<your-dietpi-ip>
   ```

2. **Install Tailscale using the official installation script:**
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   ```

   Alternatively, you can use DietPi's software installer:
   ```bash
   dietpi-software install 200
   ```
   (Tailscale is software ID #200 in DietPi-Software)

3. **Start Tailscale and authenticate:**
   ```bash
   tailscale up
   ```
   
   This will provide you with a URL to authenticate your device. Open the URL in a web browser and log in to your Tailscale account.

4. **Verify Tailscale is running:**
   ```bash
   tailscale status
   ```

### Step 2: Configure an Exit Node (if you want to route traffic)

If you want this DietPi node to route its internet traffic through another device in your Tailnet:

1. **Ensure you have an exit node available in your Tailnet.** You can configure another device as an exit node by:
   - Going to the [Tailscale admin console](https://login.tailscale.com/admin/machines)
   - Selecting a device to act as your exit node
   - Enabling "Use as exit node" in the device settings
   - OR running this on the exit node device: `sudo tailscale up --advertise-exit-node`

2. **Find your exit node's name:**
   ```bash
   tailscale status
   ```
   Look for the device you want to use as an exit node (e.g., `raspberrypi4`, `home-server`, etc.)

### Step 3: Run the Setup Script

This repository includes a comprehensive setup script that automates the NAT/Masquerade configuration and exit node setup.

1. **Download the setup script:**
   ```bash
   wget https://raw.githubusercontent.com/nthings/dietpi-tailnet/main/setup-tailscale-nat.sh
   chmod +x setup-tailscale-nat.sh
   ```

2. **Edit the script to set your exit node name** (optional):
   
   Open the script and modify the `TAILSCALE_EXIT_NODE` variable around line 204:
   ```bash
   nano setup-tailscale-nat.sh
   ```
   
   Change:
   ```bash
   TAILSCALE_EXIT_NODE="raspberrypi4"
   ```
   to your exit node's name (as shown in `tailscale status`)

3. **Run the setup script:**
   ```bash
   sudo ./setup-tailscale-nat.sh
   ```

   The script will:
   - Enable IP forwarding (IPv4 and IPv6)
   - Configure NAT/Masquerade rules for Tailscale
   - Persist iptables rules across reboots
   - Configure your exit node with LAN access enabled
   - Install and configure iptables-persistent

### Step 4: Verify the Configuration

1. **Check Tailscale status:**
   ```bash
   tailscale status
   ```
   
   You should see your exit node listed and marked as active.

2. **Test internet connectivity through the exit node:**
   ```bash
   curl ifconfig.me
   ```
   
   This should return the public IP address of your exit node, not your DietPi's local IP.

3. **Verify IP forwarding is enabled:**
   ```bash
   sysctl net.ipv4.ip_forward
   sysctl net.ipv6.conf.all.forwarding
   ```
   
   Both should return `1`.

4. **Check NAT rules:**
   ```bash
   sudo iptables -t nat -L POSTROUTING -v --line-numbers
   ```

## Manual Configuration (Alternative)

If you prefer to configure everything manually without using the script:

### Enable IP Forwarding

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Persist across reboots
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.d/99-tailscale.conf
echo "net.ipv6.conf.all.forwarding = 1" | sudo tee -a /etc/sysctl.d/99-tailscale.conf
sudo sysctl -p /etc/sysctl.d/99-tailscale.conf
```

### Configure Exit Node

```bash
# Set exit node (replace 'exit-node-name' with your exit node's hostname)
sudo tailscale set --exit-node=exit-node-name --exit-node-allow-lan-access=true
```

### Setup NAT/Masquerade (if needed)

```bash
# Install iptables-persistent
sudo apt-get update
sudo apt-get install -y iptables-persistent

# Add masquerade rules
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tailscale0 -j ACCEPT
sudo iptables -A FORWARD -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
sudo ip6tables-save | sudo tee /etc/iptables/rules.v6
```

## Advanced Features

### Static IP Configuration

The setup script includes utilities to configure a static IP that will be applied on the next boot:

```bash
# Configure static IP for next boot
sudo ./setup-tailscale-nat.sh --set-static-ip -i 192.168.1.30 -g 192.168.1.1 -n 24 -d eth0

# Check pending static IP configuration
sudo ./setup-tailscale-nat.sh --static-ip-status

# Cancel pending static IP configuration
sudo ./setup-tailscale-nat.sh --cancel-static-ip
```

### Changing Exit Node

To switch to a different exit node:

```bash
# Method 1: Edit and re-run the script
nano setup-tailscale-nat.sh  # Change TAILSCALE_EXIT_NODE variable
sudo ./setup-tailscale-nat.sh

# Method 2: Use Tailscale CLI directly
sudo tailscale set --exit-node=new-exit-node-name --exit-node-allow-lan-access=true
```

### Disable Exit Node

To stop routing traffic through an exit node:

```bash
sudo tailscale set --exit-node=
```

## Use Cases

### Home Lab Access
Configure your DietPi device to access your home network remotely by routing through a home exit node.

### Privacy-Enhanced Browsing
Route your DietPi's internet traffic through an exit node in a different location for enhanced privacy.

### Multi-Site Networking
Connect multiple DietPi devices across different locations and route traffic through a central exit node.

### IoT Device Protection
Secure IoT devices by routing their traffic through a monitored exit node.

## Troubleshooting

### Tailscale is not connecting

1. **Check Tailscale service status:**
   ```bash
   sudo systemctl status tailscaled
   ```

2. **Restart Tailscale:**
   ```bash
   sudo systemctl restart tailscaled
   tailscale up
   ```

3. **Check firewall rules:**
   ```bash
   sudo iptables -L -v -n
   ```

### Exit node is not working

1. **Verify exit node is approved** in the [Tailscale admin console](https://login.tailscale.com/admin/machines)

2. **Check current exit node status:**
   ```bash
   tailscale status --peers=false
   ```

3. **Try setting the exit node again:**
   ```bash
   sudo tailscale set --exit-node=your-exit-node-name --exit-node-allow-lan-access=true
   ```

### Cannot access local network while using exit node

Make sure you enabled LAN access when configuring the exit node:
```bash
sudo tailscale set --exit-node=your-exit-node-name --exit-node-allow-lan-access=true
```

### IP forwarding not persisting after reboot

1. **Check if the sysctl configuration file exists:**
   ```bash
   ls -la /etc/sysctl.d/99-tailscale-forwarding.conf
   ```

2. **Manually verify and reload:**
   ```bash
   sudo sysctl -p /etc/sysctl.d/99-tailscale-forwarding.conf
   ```

### iptables rules not persisting

1. **Check if iptables-persistent is installed:**
   ```bash
   dpkg -l | grep iptables-persistent
   ```

2. **Reinstall if necessary:**
   ```bash
   sudo apt-get install --reinstall iptables-persistent
   ```

3. **Manually save rules:**
   ```bash
   sudo iptables-save | sudo tee /etc/iptables/rules.v4
   sudo ip6tables-save | sudo tee /etc/iptables/rules.v6
   ```

## Script Options

The `setup-tailscale-nat.sh` script supports several options:

```bash
Usage: ./setup-tailscale-nat.sh [OPTIONS]

Options:
  (no options)           Run full NAT/Masquerade setup
  --set-static-ip        Configure static IP for next boot
      -i, --ip IP        Static IP address (required)
      -g, --gateway GW   Gateway address (required)
      -n, --netmask NM   Netmask in CIDR (default: 24)
      -d, --interface IF Network interface (default: eth0)
      --dns1 DNS         Primary DNS (default: 8.8.8.8)
      --dns2 DNS         Secondary DNS (default: 8.8.4.4)
  --cancel-static-ip     Cancel pending static IP configuration
  --static-ip-status     Show pending static IP configuration
  -h, --help             Show this help message
```

## Security Considerations

- **Exit nodes have access to all your internet traffic.** Only use exit nodes you trust.
- **Keep Tailscale updated** to ensure you have the latest security patches.
- **Use ACLs (Access Control Lists)** in your Tailscale admin console to restrict which devices can access your DietPi node.
- **Review iptables rules** regularly to ensure they match your security requirements.
- **Enable MFA** on your Tailscale account for additional security.

## Additional Resources

- [Tailscale Documentation](https://tailscale.com/kb/)
- [DietPi Documentation](https://dietpi.com/docs/)
- [Exit Nodes Explained](https://tailscale.com/kb/1103/exit-nodes/)
- [Subnet Routers](https://tailscale.com/kb/1019/subnets/)
- [Tailscale ACLs](https://tailscale.com/kb/1018/acls/)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Mauricio Alejandro Martínez Pacheco

## Support

For issues related to:
- **This script**: Open an issue in this repository
- **Tailscale**: Visit [Tailscale Support](https://tailscale.com/contact/support/)
- **DietPi**: Visit [DietPi Forums](https://dietpi.com/forum/)
