# Enhanced OpenVPN Installer

An enhanced version of the OpenVPN installer script with advanced features for WebSocket payloads, proxy configuration, and improved client management.

## Features

- **Easy Installation**: One-command installation of OpenVPN server
- **Post-Install Command**: Convenient `faizvpn` command for management
- **WebSocket Payloads**: Multiple payload options for bypassing restrictions
- **Proxy Support**: HTTP and SOCKS proxy with authentication
- **Enhanced Management**: Detailed client information and statistics
- **Backup & Restore**: Easy configuration backup and restore

## Quick Start

### Installation

```bash
# Download the script
curl -O https://raw.githubusercontent.com/Abdofaiz/scripovpn/main/openvpn-install.sh

# Make it executable
chmod +x openvpn-install.sh

# Run the installer
./openvpn-install.sh
```

After installation, use the `faizvpn` command to access the management menu.

## Management Menu

The script creates a convenient `faizvpn` command that provides access to the following options:

1. Add a new user
2. Revoke existing user
3. View connected clients
4. Change server configuration
5. Backup/Restore configuration
6. Configure Payload settings
7. Configure Proxy settings
8. Remove OpenVPN
9. Exit

## Payload Options

This enhanced script supports several payload options to help bypass network restrictions:

### 1. HTTP Header Payload
Add custom HTTP headers to your OpenVPN client configuration.

### 2. SNI Payload
Use Server Name Indication for enhanced connectivity.

### 3. Standard WebSocket Payload
Basic WebSocket upgrade request with host header.

### 4. ACL WebSocket Split Payload
Implementation of `[split]HTTP/1.1 [lf]Host: [host][lf]Upgrade: Websocket[lf][lf]` format.

### 5. GET WebSocket Payload
Implementation of:
```
GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]
```

## Proxy Configuration

The script supports HTTP and SOCKS proxies with authentication:

### HTTP Proxy
Configure an HTTP proxy with optional username/password authentication.

### SOCKS Proxy
Configure SOCKS v4/v5 proxies with optional authentication (SOCKS v5 only).

## Enhanced Client Management

### Detailed Client Listing
View client certificates with creation and expiration dates.

### Connected Clients View
See detailed statistics including:
- Real IP address
- Virtual IP address
- Connection time
- Data usage (upload/download)

## Usage Examples

### Setting Up WebSocket Payload with HTTP Proxy

1. Run the `faizvpn` command
2. Select option 6 (Configure Payload settings)
3. Choose option 5 (GET WebSocket payload)
4. Enter your host (e.g., example.com)
5. Return to main menu
6. Select option 7 (Configure Proxy settings)
7. Choose option 1 (HTTP proxy)
8. Enter proxy details
9. Return to main menu
10. Select option 1 to create a new client with these settings

### Auto-Installation

You can perform a headless installation with:

```bash
AUTO_INSTALL=y ./openvpn-install.sh
```

## Advanced Configuration

### Customizing Payload Settings
The script provides flexible payload configuration. You can customize any payload option by modifying the corresponding template.

### Backup and Restore
Use option 5 in the main menu to backup or restore your entire OpenVPN configuration.

## Troubleshooting

If you encounter issues:

1. Check that the proxy server is accessible
2. Ensure payload host is correct
3. Verify client configuration is properly loaded

## Credits

This script is based on the [angristan/openvpn-install](https://github.com/angristan/openvpn-install) script with significant enhancements.

## License

This project is licensed under the MIT License - see the original repository for details.
